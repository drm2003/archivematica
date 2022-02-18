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


METADATA_DIR = Path("objects") / "metadata"
TRANSFER_METADATA_DIR = METADATA_DIR / "transfers" / "transfer_a"
TRANSFER_SOURCE_METADATA_CSV = TRANSFER_METADATA_DIR / "source-metadata.csv"
VALID_XML = '<?xml version="1.0" encoding="UTF-8"?><foo><bar/></foo>'
INVALID_XML = '<?xml version="1.0" encoding="UTF-8"?><foo/>'
SCHEMAS = {
    "xsd": """<?xml version="1.0" encoding="UTF-8"?>
<xs:schema  xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="foo">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="bar" type="xs:string"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>
""",
    "dtd": """<!ELEMENT foo (bar)>
<!ELEMENT bar (#PCDATA)>
""",
    "rng": """<element name="foo" xmlns="http://relaxng.org/ns/structure/1.0">
  <oneOrMore>
    <element name="bar">
      <text/>
    </element>
  </oneOrMore>
</element>
""",
}


@pytest.fixture()
def make_schema_file(tmp_path):
    def _make_schema_file(schema_type):
        schema_path = tmp_path / (schema_type + "." + schema_type)
        schema_path.write_text(SCHEMAS[schema_type])
        return schema_path

    return _make_schema_file


@pytest.fixture()
def sip(tmp_path):
    sip_dir = tmp_path / "sip_dir"
    transfer_metadata_dir = sip_dir / TRANSFER_METADATA_DIR
    transfer_metadata_dir.mkdir(parents=True)
    (transfer_metadata_dir / "valid.xml").write_text(VALID_XML)
    (transfer_metadata_dir / "invalid.xml").write_text(INVALID_XML)
    return SIP.objects.create(
        uuid=uuid4(),
        sip_type="SIP",
        currentpath=str(sip_dir),
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
        sip = metsrw.FSEntry(label="sip", type="Directory")
        objects = metsrw.FSEntry(label="objects", type="Directory")
        directory = metsrw.FSEntry(label="directory", type="Directory")
        file_txt = metsrw.FSEntry(label="file.txt")
        sip.add_child(objects).add_child(directory).add_child(file_txt)
        files = [sip, objects, directory, file_txt]
        for uuid in metadata_file_uuids:
            files.append(metsrw.FSEntry(file_uuid=uuid, use="metadata"))
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


def test_disabled_settings(settings, make_mock_mets):
    mock_mets = make_mock_mets()
    objects_fsentry = mock_mets.get_file(label="objects")
    settings.METADATA_XML_VALIDATION_ENABLED = False
    mock_mets, errors = process_xml_metadata(mock_mets, "", "", "")
    assert objects_fsentry.dmdsecs == []
    assert errors == []
    settings.METADATA_XML_VALIDATION_ENABLED = True
    settings.XML_VALIDATION = {}
    mock_mets, errors = process_xml_metadata(mock_mets, "", "", "")
    assert errors == []
    assert objects_fsentry.dmdsecs == []


@pytest.mark.django_db
def test_no_source_metadata_csv(settings, make_mock_mets, sip):
    settings.METADATA_XML_VALIDATION_ENABLED = True
    settings.XML_VALIDATION = {"foo": None}
    mock_mets = make_mock_mets()
    mock_mets, errors = process_xml_metadata(mock_mets, sip.currentpath, sip.uuid, "")
    objects_fsentry = mock_mets.get_file(label="objects")
    assert errors == []
    assert objects_fsentry.dmdsecs == []


@pytest.mark.django_db
@pytest.mark.parametrize("schema", ["xsd", "dtd", "rng"])
def test_validation_success(
    settings, make_metadata_file, make_mock_mets, make_schema_file, sip, schema
):
    settings.METADATA_XML_VALIDATION_ENABLED = True
    settings.XML_VALIDATION = {"foo": str(make_schema_file(schema))}
    source_metadata_csv_contents = """filename,metadata,type
objects,valid.xml,mdtype
"""
    metadata_csv_path = sip.currentpath / TRANSFER_SOURCE_METADATA_CSV
    metadata_csv_path.write_text(source_metadata_csv_contents)
    metadata_file_rel_path = TRANSFER_METADATA_DIR / "valid.xml"
    metadata_file = make_metadata_file(metadata_file_rel_path)
    mock_mets = make_mock_mets([str(metadata_file.uuid)])
    mock_mets, errors = process_xml_metadata(mock_mets, sip.currentpath, sip.uuid, "")
    objects_fsentry = mock_mets.get_file(label="objects")
    metadata_fsentry = mock_mets.get_file(file_uuid=str(metadata_file.uuid))
    assert errors == []
    assert objects_fsentry.dmdsecs[0].status == "original"
    assert objects_fsentry.dmdsecs[0].contents.mdtype == "OTHER"
    assert objects_fsentry.dmdsecs[0].contents.othermdtype == "mdtype"
    assert objects_fsentry.dmdsecs[0].contents.document.tag == "foo"
    assert metadata_fsentry.get_premis_events()[0].event_outcome == "pass"


@pytest.mark.django_db
@pytest.mark.parametrize("schema", ["xsd", "dtd", "rng"])
def test_validation_error(
    settings, make_metadata_file, make_mock_mets, make_schema_file, sip, schema
):
    settings.METADATA_XML_VALIDATION_ENABLED = True
    settings.XML_VALIDATION = {"foo": str(make_schema_file(schema))}
    source_metadata_csv_contents = """filename,metadata,type
objects,invalid.xml,mdtype
"""
    metadata_csv_path = sip.currentpath / TRANSFER_SOURCE_METADATA_CSV
    metadata_csv_path.write_text(source_metadata_csv_contents)
    metadata_file_rel_path = TRANSFER_METADATA_DIR / "invalid.xml"
    metadata_file = make_metadata_file(metadata_file_rel_path)
    mock_mets = make_mock_mets([str(metadata_file.uuid)])
    mock_mets, errors = process_xml_metadata(mock_mets, sip.currentpath, sip.uuid, "")
    objects_fsentry = mock_mets.get_file(label="objects")
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
def test_skipped_validation(settings, make_metadata_file, make_mock_mets, sip):
    settings.METADATA_XML_VALIDATION_ENABLED = True
    settings.XML_VALIDATION = {"foo": None}
    source_metadata_csv_contents = """filename,metadata,type
objects,invalid.xml,mdtype
"""
    metadata_csv_path = sip.currentpath / TRANSFER_SOURCE_METADATA_CSV
    metadata_csv_path.write_text(source_metadata_csv_contents)
    metadata_file_rel_path = TRANSFER_METADATA_DIR / "invalid.xml"
    metadata_file = make_metadata_file(metadata_file_rel_path)
    mock_mets = make_mock_mets([str(metadata_file.uuid)])
    mock_mets, errors = process_xml_metadata(mock_mets, sip.currentpath, sip.uuid, "")
    objects_fsentry = mock_mets.get_file(label="objects")
    metadata_fsentry = mock_mets.get_file(file_uuid=str(metadata_file.uuid))
    assert errors == []
    assert objects_fsentry.dmdsecs[0].status == "original"
    assert objects_fsentry.dmdsecs[0].contents.mdtype == "OTHER"
    assert objects_fsentry.dmdsecs[0].contents.othermdtype == "mdtype"
    assert objects_fsentry.dmdsecs[0].contents.document.tag == "foo"
    assert metadata_fsentry.get_premis_events() == []


@pytest.mark.django_db
def test_validation_schema_errors(
    settings, make_metadata_file, make_mock_mets, make_schema_file, sip
):
    settings.METADATA_XML_VALIDATION_ENABLED = True
    settings.XML_VALIDATION = {"foo": "bad_path.xsd"}
    source_metadata_csv_contents = """filename,metadata,type
objects,valid.xml,mdtype
"""
    metadata_csv_path = sip.currentpath / TRANSFER_SOURCE_METADATA_CSV
    metadata_csv_path.write_text(source_metadata_csv_contents)
    metadata_file_rel_path = TRANSFER_METADATA_DIR / "valid.xml"
    metadata_file = make_metadata_file(metadata_file_rel_path)
    mock_mets = make_mock_mets([str(metadata_file.uuid)])
    mock_mets, errors = process_xml_metadata(mock_mets, sip.currentpath, sip.uuid, "")
    assert "XML schema local path bad_path.xsd must be absolute" in errors[0]
    schema_file = make_schema_file("xsd")
    schema_file.write_text("")
    settings.XML_VALIDATION = {"foo": str(schema_file)}
    mock_mets, errors = process_xml_metadata(mock_mets, sip.currentpath, sip.uuid, "")
    assert "Could not parse schema file" in errors[0]
    unk_schema_file = schema_file.with_suffix(".unk")
    unk_schema_file.write_text("")
    settings.XML_VALIDATION = {"foo": str(unk_schema_file)}
    mock_mets, errors = process_xml_metadata(mock_mets, sip.currentpath, sip.uuid, "")
    assert "Unknown XML validation schema type: unk" in errors[0]


@pytest.mark.django_db
def test_source_metadata_errors(settings, make_mock_mets, sip):
    settings.METADATA_XML_VALIDATION_ENABLED = True
    settings.XML_VALIDATION = {"foo": None}
    mock_mets = make_mock_mets()
    metadata_csv_path = sip.currentpath / TRANSFER_SOURCE_METADATA_CSV
    source_metadata_csv_contents = """filename,metadata,type
valid.xml,none
,valid.xml,none
objects,valid.xml
objects,valid.xml,
"""
    metadata_csv_path.write_text(source_metadata_csv_contents)
    mock_mets, errors = process_xml_metadata(mock_mets, sip.currentpath, sip.uuid, "")
    assert len(errors) == 4
    for error in errors:
        assert "missing the filename and/or type" in error
    source_metadata_csv_contents = """filename,metadata,type
objects,valid.xml,CUSTOM
"""
    metadata_csv_path.write_text(source_metadata_csv_contents)
    mock_mets, errors = process_xml_metadata(mock_mets, sip.currentpath, sip.uuid, "")
    assert "is using CUSTOM, a reserved type" in errors[0]
    source_metadata_csv_contents = """filename,metadata,type
objects,valid.xml,mdtype
objects,invalid.xml,mdtype
"""
    metadata_csv_path.write_text(source_metadata_csv_contents)
    mock_mets, errors = process_xml_metadata(mock_mets, sip.currentpath, sip.uuid, "")
    assert (
        "More than one entry in {} for path objects and type mdtype".format(
            metadata_csv_path
        )
        in errors[0]
    )


@pytest.mark.django_db
@pytest.mark.parametrize(
    "validation_key, should_error",
    [
        ("http://foo.com/foo_no_namespace_schema.xsd", False),
        ("http://foo.com/foo_schema.xsd", False),
        ("http://foo.com/foo_namespace.xsd", False),
        ("foo", False),
        ("bar", True),
    ],
)
def test_schema_uri_retrieval(
    settings,
    make_metadata_file,
    make_mock_mets,
    make_schema_file,
    sip,
    validation_key,
    should_error,
):
    schema_path = str(make_schema_file("xsd"))
    settings.METADATA_XML_VALIDATION_ENABLED = True
    settings.XML_VALIDATION = {validation_key: schema_path}
    source_metadata_csv_contents = """filename,metadata,type
objects,valid.xml,mdtype
"""
    metadata_csv_path = sip.currentpath / TRANSFER_SOURCE_METADATA_CSV
    metadata_csv_path.write_text(source_metadata_csv_contents)
    metadata_file_contents = """<?xml version="1.0" encoding="UTF-8"?>
<foo:foo xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:foo="http://foo.com/foo_namespace.xsd"
    xsi:schemaLocation="http://foo.com/foo http://foo.com/foo_schema.xsd"
    xsi:noNamespaceSchemaLocation="http://foo.com/foo_no_namespace_schema.xsd"
/>
"""
    metadata_file_rel_path = TRANSFER_METADATA_DIR / "valid.xml"
    metadata_file = make_metadata_file(metadata_file_rel_path)
    metadata_file_path = sip.currentpath / metadata_file_rel_path
    metadata_file_path.write_text(metadata_file_contents)
    mock_mets = make_mock_mets([str(metadata_file.uuid)])
    mock_mets, errors = process_xml_metadata(mock_mets, sip.currentpath, sip.uuid, "")
    metadata_fsentry = mock_mets.get_file(file_uuid=str(metadata_file.uuid))
    if should_error:
        assert "XML validation schema not found for keys:" in str(errors[0])
        assert metadata_fsentry.get_premis_events() == []
        return
    assert (
        'validation-source="{}";'.format(schema_path)
        in metadata_fsentry.get_premis_events()[0].event_detail
    )


@pytest.mark.django_db
def test_multiple_dmdsecs(settings, make_metadata_file, make_mock_mets, sip):
    mdkeys = ["foo", "foo_2", "foo_3"]
    settings.METADATA_XML_VALIDATION_ENABLED = True
    settings.XML_VALIDATION = {}
    csv_contents = "filename,metadata,type\n"
    metadata_file_uuids = []
    for mdkey in mdkeys:
        settings.XML_VALIDATION[mdkey] = None
        csv_contents += "objects,{}.xml,{}\n".format(mdkey, mdkey)
        csv_contents += "objects/directory,{}.xml,{}\n".format(mdkey, mdkey)
        csv_contents += "objects/directory/file.txt,{}.xml,{}\n".format(mdkey, mdkey)
        metadata_file_rel_path = TRANSFER_METADATA_DIR / "{}.xml".format(mdkey)
        metadata_file = make_metadata_file(metadata_file_rel_path)
        metadata_file_path = sip.currentpath / metadata_file_rel_path
        metadata_file_path.write_text(
            '<?xml version="1.0" encoding="UTF-8"?><{}/>'.format(mdkey)
        )
        metadata_file_uuids.append(str(metadata_file.uuid))
    metadata_csv_path = sip.currentpath / TRANSFER_SOURCE_METADATA_CSV
    metadata_csv_path.write_text(csv_contents)
    mock_mets = make_mock_mets(metadata_file_uuids)
    mock_mets, errors = process_xml_metadata(mock_mets, sip.currentpath, sip.uuid, "")
    assert errors == []
    for label in ["objects", "directory", "file.txt"]:
        fsentry = mock_mets.get_file(label=label)
        assert len(fsentry.dmdsecs) == 3
        for mdkey in mdkeys:
            dmdsec = fsentry.dmdsecs_mapping["OTHER_{}".format(mdkey)][0]
            assert dmdsec.contents.othermdtype == mdkey
            assert dmdsec.contents.document.tag == mdkey


@pytest.mark.django_db
def test_reingest(settings, make_schema_file, make_metadata_file, make_mock_mets, sip):
    settings.METADATA_XML_VALIDATION_ENABLED = True
    settings.XML_VALIDATION = {"foo": str(make_schema_file("xsd"))}
    source_metadata_csv_contents = """filename,metadata,type
objects,valid.xml,mdtype
"""
    metadata_csv_path = sip.currentpath / METADATA_DIR / "source-metadata.csv"
    metadata_csv_path.write_text(source_metadata_csv_contents)
    valid_md_file_rel_path = METADATA_DIR / "valid.xml"
    valid_md_file = make_metadata_file(valid_md_file_rel_path)
    (sip.currentpath / valid_md_file_rel_path).write_text(VALID_XML)
    invalid_md_file_rel_path = METADATA_DIR / "invalid.xml"
    invalid_md_file = make_metadata_file(invalid_md_file_rel_path)
    (sip.currentpath / invalid_md_file_rel_path).write_text(INVALID_XML)
    mock_mets = make_mock_mets([str(valid_md_file.uuid), str(invalid_md_file.uuid)])
    objects_fsentry = mock_mets.get_file(label="objects")
    objects_fsentry.add_dmdsec("<foo><bar/></foo>", "OTHER", othermdtype="mdtype")
    valid_md_fsentry = mock_mets.get_file(file_uuid=str(valid_md_file.uuid))
    invalid_md_fsentry = mock_mets.get_file(file_uuid=str(invalid_md_file.uuid))
    mock_mets, errors = process_xml_metadata(
        mock_mets, sip.currentpath, sip.uuid, "REIN"
    )
    assert errors == []
    assert len(objects_fsentry.dmdsecs) == 2
    assert len(objects_fsentry.dmdsecs_mapping["OTHER_mdtype"]) == 2
    assert objects_fsentry.dmdsecs[0].status == "original-superseded"
    assert objects_fsentry.dmdsecs[1].status == "update"
    assert objects_fsentry.dmdsecs[0].group_id is not None
    assert objects_fsentry.dmdsecs[0].group_id == objects_fsentry.dmdsecs[1].group_id
    assert len(valid_md_fsentry.get_premis_events()) == 1
    assert valid_md_fsentry.get_premis_events()[0].event_outcome == "pass"
    mock_mets, errors = process_xml_metadata(
        mock_mets, sip.currentpath, sip.uuid, "REIN"
    )
    assert errors == []
    assert len(objects_fsentry.dmdsecs) == 3
    assert len(objects_fsentry.dmdsecs_mapping["OTHER_mdtype"]) == 3
    assert objects_fsentry.dmdsecs[1].status == "update-superseded"
    assert objects_fsentry.dmdsecs[2].status == "update"
    assert objects_fsentry.dmdsecs[0].group_id == objects_fsentry.dmdsecs[2].group_id
    assert len(valid_md_fsentry.get_premis_events()) == 2
    assert valid_md_fsentry.get_premis_events()[1].event_outcome == "pass"
    source_metadata_csv_contents = """filename,metadata,type
objects,,mdtype
"""
    metadata_csv_path.write_text(source_metadata_csv_contents)
    mock_mets, errors = process_xml_metadata(
        mock_mets, sip.currentpath, sip.uuid, "REIN"
    )
    assert errors == []
    assert len(objects_fsentry.dmdsecs) == 3
    assert len(objects_fsentry.dmdsecs_mapping["OTHER_mdtype"]) == 3
    assert objects_fsentry.dmdsecs[2].status == "deleted"
    assert len(valid_md_fsentry.get_premis_events()) == 2
    source_metadata_csv_contents = """filename,metadata,type
objects,invalid.xml,mdtype
"""
    metadata_csv_path.write_text(source_metadata_csv_contents)
    mock_mets, errors = process_xml_metadata(
        mock_mets, sip.currentpath, sip.uuid, "REIN"
    )
    assert len(errors) > 0
    assert len(objects_fsentry.dmdsecs) == 3
    assert len(objects_fsentry.dmdsecs_mapping["OTHER_mdtype"]) == 3
    assert objects_fsentry.dmdsecs[2].status == "deleted"
    assert len(invalid_md_fsentry.get_premis_events()) == 1
    assert invalid_md_fsentry.get_premis_events()[0].event_outcome == "fail"
    settings.XML_VALIDATION = {"foo": None}
    mock_mets, errors = process_xml_metadata(
        mock_mets, sip.currentpath, sip.uuid, "REIN"
    )
    assert errors == []
    assert len(objects_fsentry.dmdsecs) == 4
    assert len(objects_fsentry.dmdsecs_mapping["OTHER_mdtype"]) == 4
    assert objects_fsentry.dmdsecs[2].status == "deleted-superseded"
    assert objects_fsentry.dmdsecs[3].status == "update"
    assert objects_fsentry.dmdsecs[0].group_id == objects_fsentry.dmdsecs[3].group_id
    assert len(invalid_md_fsentry.get_premis_events()) == 1
