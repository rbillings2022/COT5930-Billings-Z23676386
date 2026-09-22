"""Unit tests for the local email loader."""

from unittest.mock import patch, MagicMock

from langchain_core.documents import Document
from email_loader import EmailLoader


def test_load_returns_langchain_documents_from_eml_files(tmp_path) -> None:
    """Verify the loader converts mocked email files into documents."""
    # Create two empty placeholder .eml files so the directory scan finds them.
    # Their content doesn't matter since UnstructuredEmailLoader is mocked.
    (tmp_path / "email1.eml").write_text("placeholder")
    (tmp_path / "email2.eml").write_text("placeholder")

    # Fake return values for each mocked UnstructuredEmailLoader instance.
    fake_docs = {
        "email1.eml": [Document(page_content="Body of email 1", metadata={"subject": "Hi"})],
        "email2.eml": [Document(page_content="Body of email 2", metadata={"subject": "Bye"})],
    }

    def fake_loader_factory(path: str):
        """Return a MagicMock whose .load() yields the matching fake document."""
        filename = path.split("\\")[-1].split("/")[-1]  # handle both path styles
        mock_loader = MagicMock()
        mock_loader.load.return_value = fake_docs[filename]
        return mock_loader

    with patch(
        "email_loader.UnstructuredEmailLoader", side_effect=fake_loader_factory
    ) as mock_class:
        documents = EmailLoader(directory=str(tmp_path)).load()

    # Verify both files were processed and content came through correctly.
    assert mock_class.call_count == 2
    assert [document.page_content for document in documents] == [
        "Body of email 1",
        "Body of email 2",
    ]
    assert documents[0].metadata["source_file"] == "email1.eml"
    assert documents[1].metadata["source_file"] == "email2.eml"


def test_init_raises_on_invalid_directory() -> None:
    """Verify constructing the loader with a bad path fails fast."""
    try:
        EmailLoader(directory="this/path/does/not/exist")
        assert False, "Expected ValueError"
    except ValueError:
        pass