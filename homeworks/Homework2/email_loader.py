"""A small email-backed document loader built on UnstructuredEmailLoader."""

from __future__ import annotations

from pathlib import Path

from langchain_community.document_loaders import UnstructuredEmailLoader
from langchain_core.documents import Document


class EmailLoader:
    """Load .eml files from a directory using UnstructuredEmailLoader.

    Network/disk access is deferred until :meth:`load` so constructing a
    loader is inexpensive and side-effect free.
    """

    def __init__(self, directory: str, glob_pattern: str = "*.eml") -> None:
        """Store the target directory and validate it exists.

        Args:
            directory: Path to a folder containing .eml files.
            glob_pattern: Filename pattern used to select email files.
        """
        path = Path(directory)
        if not path.is_dir():
            raise ValueError(f"{directory!r} is not a valid directory")

        self.directory = path
        self.glob_pattern = glob_pattern

    def load(self) -> list[Document]:
        """Parse each matching .eml file and return one Document per email."""
        documents: list[Document] = []

        for email_path in sorted(self.directory.glob(self.glob_pattern)):
            loader = UnstructuredEmailLoader(str(email_path))
            loaded = loader.load()  # UnstructuredEmailLoader returns list[Document]

            for doc in loaded:
                # Enrich metadata with the source filename for traceability.
                doc.metadata["source_file"] = email_path.name
                documents.append(doc)

        return documents


if __name__ == "__main__":
    # Live example: requires a local directory of sample .eml files.
    loader = EmailLoader(directory="rag_data/emails")
    documents = loader.load()

    for index, document in enumerate(documents, start=1):
        print(document.page_content[:300])
        print("---")
        print(f"Document {index} metadata:")
        print(document.metadata)