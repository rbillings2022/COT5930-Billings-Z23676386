"""Chainlit-based chat application for a personal document Q&A assistant.

This app answers questions using retrieval-augmented generation (RAG) over
a Chroma vector database built by ``07_rag_loaddb.py``. Supported sources
include Wikipedia, GitHub files, YouTube transcripts, local documents, and
emails loaded via the custom :class:`EmailLoader`.
"""

import os

from langchain_chroma import Chroma
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough
from langchain_core.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_google_vertexai import VertexAIEmbeddings
import chainlit as cl

# Configure the chat model used to answer questions from retrieved context.
llm = ChatGoogleGenerativeAI(model=os.getenv("GOOGLE_MODEL"))

# Open the persisted vector database (built by 07_rag_loaddb.py) and create
# a retriever from it. Uses the same embedding function it was built with.
vectorstore = Chroma(
    persist_directory="./rag_data/.chromadb",
    embedding_function=VertexAIEmbeddings(
        model_name="gemini-embedding-001",
        project=os.getenv("GOOGLE_CLOUD_PROJECT"),
        location="us-west1",
    ),
)

retriever = vectorstore.as_retriever()

# Local prompt template so the RAG response length and fallback behavior are explicit.
prompt = ChatPromptTemplate.from_template(
    """You are an assistant for question-answering tasks.
Use the following pieces of retrieved context to answer the question.
If you don't know the answer, just say that you don't know.
Use three sentences maximum and keep the answer concise.

Question: {question}

Context: {context}

Answer:"""
)


def format_docs(docs):
    """Join retrieved document contents into one prompt context string."""
    return "\n\n".join(doc.page_content for doc in docs)


# Retrieve context, fill the prompt, call the model, and parse plain text.
rag_chain = (
    {"context": retriever | format_docs, "question": RunnablePassthrough()}
    | prompt
    | llm
    | StrOutputParser()
)


@cl.on_chat_start
async def on_chat_start() -> None:
    """Send a welcome message listing the currently indexed sources."""
    document_data_sources = set()
    for doc_metadata in retriever.vectorstore.get()["metadatas"]:
        document_data_sources.add(doc_metadata["source"])

    sources_list = "\n".join(f"- {src}" for src in sorted(document_data_sources))
    welcome_text = (
        "**Welcome to my custom RAG assistant.**\n\n"
        "Ask me anything from the documents I have indexed, including "
        "emails loaded via a custom email loader.\n\n"
        f"**Indexed sources:**\n{sources_list}"
    )
    await cl.Message(content=welcome_text).send()


@cl.on_message
async def on_message(message: cl.Message) -> None:
    """Handle a user message by returning a RAG-generated answer."""
    user_query = message.content
    answer = rag_chain.invoke(user_query)
    await cl.Message(content=answer).send()