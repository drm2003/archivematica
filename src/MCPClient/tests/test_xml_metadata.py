#!/usr/bin/env python
"""
Tests for XML metadata management on the METS creation process:

archivematicaCreateMETSMetadataXML.process_xml_metadata()
"""

from pathlib import Path
from uuid import uuid4

import metsrw
import pytest

from main.models import File, SIP

from archivematicaCreateMETSMetadataXML import process_xml_metadata


FIXTURES = Path(__file__).parent.resolve() / "fixtures" / "xml_metadata"
SIP_DIR = FIXTURES / "sip_dir"
SIP_UUID = uuid4()
BASE_METS = str(FIXTURES / "base_mets.xml")
METADATA_DIR = SIP_DIR / "objects" / "metadata"
TRANSFER_METADATA_DIR = METADATA_DIR / "transfers" / "transfer_a"
TRANSFER_SOURCE_METADATA_CSV = TRANSFER_METADATA_DIR / "source-metadata.csv"


@pytest.fixture()
def sip():
    return SIP.objects.create(
        uuid=SIP_UUID,
        sip_type="SIP",
        currentpath=SIP_DIR,
    )


@pytest.fixture()
def make_metadata_file(sip):
    def _make_metadata_file(rel_path):
        return File.objects.create(
            uuid=uuid4(),
            sip_id=sip.uuid,
            currentlocation="%SIPDirectory%{}".format(rel_path),
        )

    return _make_metadata_file


def update_source_metadata_csv(csv_path, contents):
    with open(csv_path, "w") as f:
        f.write(contents)


def add_metadata_file_to_mets(mets, metadata_file_rel_path, metadata_file):
    md_fsentry = metsrw.FSEntry(
        path=metadata_file_rel_path,
        use="metadata",
        file_uuid=str(metadata_file.uuid),
    )
    mets.append(md_fsentry)
    return md_fsentry


def test_invalid_settings(settings):
    settings.METADATA_XML_VALIDATION_ENABLED = True
    mets = metsrw.METSDocument.fromfile(BASE_METS)
    with pytest.raises(AttributeError) as error:
        process_xml_metadata(mets, SIP_DIR, SIP_UUID, "sip_type")
    assert "object has no attribute 'XML_VALIDATION'" in str(error)


def test_disabled_settings(settings):
    settings.METADATA_XML_VALIDATION_ENABLED = False
    mets = metsrw.METSDocument.fromfile(BASE_METS)
    objects = mets.get_file(label="objects", type="Directory")
    mets, errors = process_xml_metadata(mets, SIP_DIR, SIP_UUID, "sip_type")
    assert objects.dmdsecs == []
    assert errors == []
    settings.METADATA_XML_VALIDATION_ENABLED = True
    settings.XML_VALIDATION = {}
    mets, errors = process_xml_metadata(mets, SIP_DIR, SIP_UUID, "sip_type")
    assert errors == []
    assert objects.dmdsecs == []


@pytest.mark.django_db
@pytest.mark.parametrize("schema", ["xsd", "dtd", "rng"])
def test_validation_success(settings, make_metadata_file, schema):
    settings.METADATA_XML_VALIDATION_ENABLED = True
    settings.XML_VALIDATION = {
        "foo": str(FIXTURES / "schemas" / (schema + "." + schema)),
    }
    source_metadata_csv_contents = """filename,metadata,type
objects,valid.xml,mdtype
"""
    update_source_metadata_csv(
        TRANSFER_SOURCE_METADATA_CSV, source_metadata_csv_contents
    )
    metadata_file_rel_path = (TRANSFER_METADATA_DIR / "valid.xml").relative_to(SIP_DIR)
    metadata_file = make_metadata_file(metadata_file_rel_path)
    mets = metsrw.METSDocument.fromfile(BASE_METS)
    md_fsentry = add_metadata_file_to_mets(mets, metadata_file_rel_path, metadata_file)
    objects = mets.get_file(label="objects", type="Directory")
    mets, errors = process_xml_metadata(mets, SIP_DIR, SIP_UUID, "sip_type")
    assert errors == []
    assert objects.dmdsecs[0].status == "original"
    assert objects.dmdsecs[0].contents.mdtype == "OTHER"
    assert objects.dmdsecs[0].contents.othermdtype == "mdtype"
    assert objects.dmdsecs[0].contents.document.tag == "foo"
    assert md_fsentry.get_premis_events()[0].event_outcome == "pass"


@pytest.mark.django_db
@pytest.mark.parametrize("schema", ["xsd", "dtd", "rng"])
def test_validation_error(settings, make_metadata_file, schema):
    settings.METADATA_XML_VALIDATION_ENABLED = True
    settings.XML_VALIDATION = {
        "foo": str(FIXTURES / "schemas" / (schema + "." + schema)),
    }
    source_metadata_csv_contents = """filename,metadata,type
objects,invalid.xml,mdtype
"""
    update_source_metadata_csv(
        TRANSFER_SOURCE_METADATA_CSV, source_metadata_csv_contents
    )
    metadata_file_rel_path = (TRANSFER_METADATA_DIR / "invalid.xml").relative_to(
        SIP_DIR
    )
    metadata_file = make_metadata_file(metadata_file_rel_path)
    mets = metsrw.METSDocument.fromfile(BASE_METS)
    md_fsentry = add_metadata_file_to_mets(mets, metadata_file_rel_path, metadata_file)
    objects = mets.get_file(label="objects", type="Directory")
    mets, errors = process_xml_metadata(mets, SIP_DIR, SIP_UUID, "sip_type")
    assert len(errors) > 0
    assert objects.dmdsecs == []
    assert md_fsentry.get_premis_events()[0].event_outcome == "fail"
    for error in errors:
        assert str(error) in md_fsentry.get_premis_events()[0].event_outcome_detail_note


@pytest.mark.django_db
def test_skipped_validation(settings, make_metadata_file):
    settings.METADATA_XML_VALIDATION_ENABLED = True
    settings.XML_VALIDATION = {"foo": None}
    source_metadata_csv_contents = """filename,metadata,type
objects,invalid.xml,none
"""
    update_source_metadata_csv(
        TRANSFER_SOURCE_METADATA_CSV, source_metadata_csv_contents
    )
    metadata_file_rel_path = (TRANSFER_METADATA_DIR / "invalid.xml").relative_to(
        SIP_DIR
    )
    metadata_file = make_metadata_file(metadata_file_rel_path)
    mets = metsrw.METSDocument.fromfile(BASE_METS)
    md_fsentry = add_metadata_file_to_mets(mets, metadata_file_rel_path, metadata_file)
    objects = mets.get_file(label="objects", type="Directory")
    mets, errors = process_xml_metadata(mets, SIP_DIR, SIP_UUID, "sip_type")
    assert errors == []
    assert objects.dmdsecs[0].status == "original"
    assert objects.dmdsecs[0].contents.mdtype == "OTHER"
    assert objects.dmdsecs[0].contents.othermdtype == "none"
    assert objects.dmdsecs[0].contents.document.tag == "foo"
    assert md_fsentry.get_premis_events() == []
