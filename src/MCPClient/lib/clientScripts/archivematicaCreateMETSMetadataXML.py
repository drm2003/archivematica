#!/usr/bin/env python
#
# This file is part of Archivematica.
#
# Copyright 2010-2021 Artefactual Systems Inc. <http://artefactual.com>
#
# Archivematica is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Archivematica is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Archivematica. If not, see <http://www.gnu.org/licenses/>.

"""Management of XML metadata files."""

import csv
from lxml import etree
import os
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen
from uuid import uuid4

import create_mets_v2 as createmets2

from databaseFunctions import insertIntoEvents

from django.conf import settings as mcpclient_settings
from main import models


def process_xml_metadata(mets, sip_dir, sip_uuid, sip_type):
    if (
        not mcpclient_settings.METADATA_XML_VALIDATION_ENABLED
        or not mcpclient_settings.XML_VALIDATION
    ):
        return mets, []
    xml_metadata_mapping, xml_metadata_errors = _get_xml_metadata_mapping(
        sip_dir, reingest="REIN" in sip_type
    )
    for fsentry in mets.all_files():
        if fsentry.use != "original" and fsentry.type != "Directory":
            continue
        path = fsentry.path
        if not path:
            dirs = []
            fsentry_loop = fsentry
            while fsentry_loop.parent:
                dirs.insert(0, fsentry_loop.label)
                fsentry_loop = fsentry_loop.parent
            path = os.sep.join(dirs)
        if path not in xml_metadata_mapping:
            continue
        dmdsec_mapping = {}
        for dmdsec in fsentry.dmdsecs:
            mdwrap = dmdsec.contents
            othermdtype = getattr(mdwrap, "othermdtype", None)
            if othermdtype:
                if othermdtype not in dmdsec_mapping:
                    dmdsec_mapping[othermdtype] = []
                dmdsec_mapping[othermdtype].append(dmdsec)
        for xml_type, xml_path in xml_metadata_mapping[path].items():
            if not xml_path and xml_type in dmdsec_mapping:
                latest_date = ""
                latest_sec = None
                for sec in dmdsec_mapping[xml_type]:
                    date = getattr(sec, "created", "")
                    if not latest_date or date > latest_date:
                        latest_date = date
                        latest_sec = sec
                latest_sec.status = "deleted"
                continue
            tree = etree.parse(str(xml_path))
            try:
                schema_uri = _get_schema_uri(tree)
            except ValueError as err:
                xml_metadata_errors.append(err)
                continue
            if schema_uri:
                valid, errors = _validate_xml(tree, schema_uri)
                event_data = {
                    "eventType": "validation",
                    "eventDetail": 'type="metadata"; validation-source-type="'
                    + schema_uri.split(".")[-1]
                    + '"; validation-source="'
                    + schema_uri
                    + '"; program="lxml"; version="'
                    + etree.__version__
                    + '"',
                    "eventOutcome": "pass" if valid else "fail",
                    "eventOutcomeDetailNote": "\n".join([str(err) for err in errors]),
                }
                xml_rel_path = xml_path.relative_to(sip_dir)
                try:
                    file_object = models.File.objects.get(
                        sip_id=sip_uuid,
                        currentlocation="%SIPDirectory%{}".format(xml_rel_path),
                    )
                except models.File.DoesNotExist:
                    xml_metadata_errors.append(
                        "No uuid for file: {}".format(xml_rel_path)
                    )
                    continue
                event_object = insertIntoEvents(file_object.uuid, **event_data)
                metadata_fsentry = mets.get_file(file_uuid=file_object.uuid)
                metadata_fsentry.add_premis_event(createmets2.createEvent(event_object))
                if not valid:
                    xml_metadata_errors += errors
                    continue
            dmdsec = fsentry.add_dmdsec(tree.getroot(), "OTHER", othermdtype=xml_type)
            dmdsec.status = "update" if "REIN" in sip_type else "original"
            if xml_type in dmdsec_mapping:
                group_id = getattr(dmdsec_mapping[xml_type][0], "group_id", "")
                if not group_id:
                    group_id = str(uuid4())
                dmdsec.group_id = group_id
                for previous_dmdsec in dmdsec_mapping[xml_type]:
                    previous_dmdsec.group_id = group_id
                    status = previous_dmdsec.status
                    # TODO: check why status is None in some cases where it shouldn't
                    if not status:
                        status = "original"
                    if not status.endswith("-superseded"):
                        previous_dmdsec.status = status + "-superseded"
    return mets, xml_metadata_errors


def _get_xml_metadata_mapping(sip_path, reingest=False):
    """Get a mapping of files/dirs in the SIP and their related XML files.

    On initial ingests, it looks for such mapping in source-metadata.csv
    files located on each transfer metadata folder. On reingest it only
    considers the source-metadata.csv file in the main metadata folder.

    Example source-metadata.csv:

    filename,metadata,type
    objects,objects_metadata.xml,metadata_type
    objects/dir,dir_metadata.xml,metadata_type
    objects/dir/file.pdf,file_metadata_a.xml,metadata_type_a
    objects/dir/file.pdf,file_metadata_b.xml,metadata_type_b

    Example dict returned:

    {
        "objects": {"metadata_type": Path("/path/to/objects_metadata.xml")},
        "objects/dir": {"metadata_type": Path("/path/to/dir_metadata.xml")},
        "objects/dir/file.pdf": {
            "metadata_type_a": Path("/path/to/file_metadata_a.xml"),
            "metadata_type_b": Path("/path/to/file_metadata_b.xml"),
        },
    }

    :param str sip_path: Absolute path to the SIP.
    :param bool reingest: Boolean to indicate if it's a reingest.
    :return dict, list: Dictionary with File/dir path -> dict of type -> metadata
    file pathlib Path, and list with errors (if a CSV row is missing the filename
    or type, or if there is more than one entry for the same filename and type).
    """
    mapping = {}
    errors = []
    source_metadata_paths = []
    metadata_path = Path(sip_path) / "objects" / "metadata"
    transfers_metadata_path = metadata_path / "transfers"
    if reingest:
        source_metadata_paths.append(metadata_path / "source-metadata.csv")
    elif transfers_metadata_path.is_dir():
        for dir_ in transfers_metadata_path.iterdir():
            source_metadata_paths.append(dir_ / "source-metadata.csv")
    for source_metadata_path in source_metadata_paths:
        if not source_metadata_path.is_file():
            continue
        with source_metadata_path.open() as f:
            reader = csv.DictReader(f)
            for row in reader:
                if not all(k in row and row[k] for k in ["filename", "type"]):
                    errors.append(
                        "A row in {} is missing the filename and/or type".format(
                            source_metadata_path
                        )
                    )
                    continue
                if row["filename"] not in mapping:
                    mapping[row["filename"]] = {}
                elif row["type"] in mapping[row["filename"]]:
                    errors.append(
                        "More than one entry in {} for path {} and type {}".format(
                            source_metadata_path, row["filename"], row["type"]
                        )
                    )
                    continue
                if row["metadata"]:
                    row["metadata"] = source_metadata_path.parent / row["metadata"]
                mapping[row["filename"]][row["type"]] = row["metadata"]
    return mapping, errors


def _get_schema_uri(tree):
    XSI = "http://www.w3.org/2001/XMLSchema-instance"
    VALIDATION = mcpclient_settings.XML_VALIDATION
    key = None
    checked_keys = []
    schema_location = tree.xpath(
        "/*/@xsi:noNamespaceSchemaLocation", namespaces={"xsi": XSI}
    )
    if schema_location:
        key = schema_location[0].strip()
        checked_keys.append(key)
    if not key or key not in VALIDATION:
        schema_location = tree.xpath("/*/@xsi:schemaLocation", namespaces={"xsi": XSI})
        if schema_location:
            key = schema_location[0].strip().split()[-1]
            checked_keys.append(key)
    if not key or key not in VALIDATION:
        key = tree.xpath("namespace-uri(.)")
        checked_keys.append(key)
    if not key or key not in VALIDATION:
        key = tree.xpath("local-name(.)")
        checked_keys.append(key)
    if not key or key not in VALIDATION:
        raise ValueError(
            "XML validation schema not found for keys: {}".format(checked_keys)
        )
    return VALIDATION[key]


def _validate_xml(tree, schema_uri):
    schema_type = schema_uri.split(".")[-1]
    parse_result = urlparse(schema_uri)
    if not parse_result.scheme and schema_uri == parse_result.path:
        # URI is a local file
        try:
            schema_uri = Path(schema_uri).as_uri()
        except ValueError:
            return False, [
                "XML schema local path {} must be absolute".format(schema_uri)
            ]
    try:
        with urlopen(schema_uri) as f:
            if schema_type == "dtd":
                schema = etree.DTD(f)
            elif schema_type == "xsd":
                schema_contents = etree.parse(f)
                schema = etree.XMLSchema(schema_contents)
            elif schema_type == "rng":
                schema_contents = etree.parse(f)
                schema = etree.RelaxNG(schema_contents)
            else:
                return False, [
                    "Unknown XML validation schema type: {}".format(schema_type)
                ]
    except etree.LxmlError as err:
        return False, ["Could not parse schema file: {}".format(schema_uri), err]
    if not schema.validate(tree):
        return False, schema.error_log
    return True, []
