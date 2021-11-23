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
from pathlib import Path


def get_xml_metadata_files_mapping(sip_path, reingest=False):
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
    :return dict: File/dir path -> dict of type -> metadata file pathlib Path.
    :raises ValueError: If a CSV row is missing the filename or type, or if
    there is more than one entry for the same filename and type.
    """
    mapping = {}
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
                    raise ValueError(
                        "A row in {} is missing the filename and/or type".format(
                            source_metadata_path
                        )
                    )
                if row["filename"] not in mapping:
                    mapping[row["filename"]] = {}
                elif row["type"] in mapping[row["filename"]]:
                    raise ValueError(
                        "More than one entry in {} for path {} and type {}".format(
                            source_metadata_path, row["filename"], row["type"]
                        )
                    )
                if row["metadata"]:
                    row["metadata"] = source_metadata_path.parent / row["metadata"]
                mapping[row["filename"]][row["type"]] = row["metadata"]
    return mapping
