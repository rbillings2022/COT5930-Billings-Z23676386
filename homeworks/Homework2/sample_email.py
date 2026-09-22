from email.message import EmailMessage

msg = EmailMessage()
msg["Subject"] = "Quarterly security review reminder"
msg["From"] = "alice@example.com"
msg["To"] = "bob@example.com"
msg["Date"] = "Mon, 15 Sep 2025 09:30:00 -0400"
msg.set_content(
    "Hi Bob,\n\nJust a reminder that the Q3 security review is due Friday. "
    "Please make sure the patch logs are attached.\n\nThanks,\nAlice"
)

with open("rag_data/emails/email1.eml", "wb") as f:
    f.write(bytes(msg))