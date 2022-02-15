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


@pytest.fixture()
def make_mock_mets(mocker):
    def _make_mock_mets(metadata_file_uuids=[]):
        files = [metsrw.FSEntry(path="objects")]
        for uuid in metadata_file_uuids:
            files.append(metsrw.FSEntry(file_uuid=uuid))
        mock_mets = mocker.Mock()
        mock_mets.all_files.return_value = files
        mock_mets.get_file.side_effect = lambda **kwargs: next(
            (
                f
                for f in files
                if all(v == getattr(f, k, None) for k, v in kwargs.items())
            ),
            None,
        )
        return mock_mets

    return _make_mock_mets


def update_source_metadata_csv(csv_path, contents):
    with open(csv_path, "w") as f:
        f.write(contents)


def test_invalid_settings(settings):
    settings.METADATA_XML_VALIDATION_ENABLED = True
    with pytest.raises(AttributeError) as error:
        process_xml_metadata("fake_mets", SIP_DIR, SIP_UUID, "sip_type")
    assert "object has no attribute 'XML_VALIDATION'" in str(error)


def test_disabled_settings(settings, make_mock_mets):
    mock_mets = make_mock_mets()
    objects_fsentry = mock_mets.get_file(path="objects")
    settings.METADATA_XML_VALIDATION_ENABLED = False
    mock_mets, errors = process_xml_metadata(mock_mets, SIP_DIR, SIP_UUID, "sip_type")
    assert objects_fsentry.dmdsecs == []
    assert errors == []
    settings.METADATA_XML_VALIDATION_ENABLED = True
    settings.XML_VALIDATION = {}
    mock_mets, errors = process_xml_metadata(mock_mets, SIP_DIR, SIP_UUID, "sip_type")
    assert errors == []
    assert objects_fsentry.dmdsecs == []


@pytest.mark.django_db
@pytest.mark.parametrize("schema", ["xsd", "dtd", "rng"])
def test_validation_success(settings, make_metadata_file, make_mock_mets, schema):
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
    mock_mets = make_mock_mets([str(metadata_file.uuid)])
    mock_mets, errors = process_xml_metadata(mock_mets, SIP_DIR, SIP_UUID, "sip_type")
    objects_fsentry = mock_mets.get_file(path="objects")
    metadata_fsentry = mock_mets.get_file(file_uuid=str(metadata_file.uuid))
    assert errors == []
    assert objects_fsentry.dmdsecs[0].status == "original"
    assert objects_fsentry.dmdsecs[0].contents.mdtype == "OTHER"
    assert objects_fsentry.dmdsecs[0].contents.othermdtype == "mdtype"
    assert objects_fsentry.dmdsecs[0].contents.document.tag == "foo"
    assert metadata_fsentry.get_premis_events()[0].event_outcome == "pass"


@pytest.mark.django_db
@pytest.mark.parametrize("schema", ["xsd", "dtd", "rng"])
def test_validation_error(settings, make_metadata_file, make_mock_mets, schema):
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
    mock_mets = make_mock_mets([str(metadata_file.uuid)])
    mock_mets, errors = process_xml_metadata(mock_mets, SIP_DIR, SIP_UUID, "sip_type")
    objects_fsentry = mock_mets.get_file(path="objects")
    metadata_fsentry = mock_mets.get_file(file_uuid=str(metadata_file.uuid))
    assert len(errors) > 0
    assert objects_fsentry.dmdsecs == []
    assert metadata_fsentry.get_premis_events()[0].event_outcome == "fail"
    for error in errors:
        assert (
            str(error)
            in metadata_fsentry.get_premis_events()[0].event_outcome_detail_note
        )


@pytest.mark.django_db
def test_skipped_validation(settings, make_metadata_file, make_mock_mets):
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
    mock_mets = make_mock_mets([str(metadata_file.uuid)])
    mock_mets, errors = process_xml_metadata(mock_mets, SIP_DIR, SIP_UUID, "sip_type")
    objects_fsentry = mock_mets.get_file(path="objects")
    metadata_fsentry = mock_mets.get_file(file_uuid=str(metadata_file.uuid))
    assert errors == []
    assert objects_fsentry.dmdsecs[0].status == "original"
    assert objects_fsentry.dmdsecs[0].contents.mdtype == "OTHER"
    assert objects_fsentry.dmdsecs[0].contents.othermdtype == "none"
    assert objects_fsentry.dmdsecs[0].contents.document.tag == "foo"
    assert metadata_fsentry.get_premis_events() == []
