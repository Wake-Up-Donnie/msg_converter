import os
import mailparser
from datetime import datetime
import independentsoft.msg as msg
import base64

def eml_to_msg(eml_path, msg_path):
    # Parse the .eml file
    mail = mailparser.parse_from_file(eml_path)

    # Create a new .msg message
    message = msg.Message()
    
    # Set sender
    if mail.from_ and len(mail.from_) > 0:
        message.sender_name = mail.from_[0][0] if mail.from_[0][0] else mail.from_[0][1]
        message.sender_email_address = mail.from_[0][1]

    # Set recipients
    if mail.to:
        recipients = []
        for to_addr in mail.to:
            recipient = msg.Recipient()
            recipient.display_name = to_addr[0] if to_addr[0] else to_addr[1]
            recipient.email_address = to_addr[1]
            recipient.recipient_type = msg.RecipientType.TO
            recipients.append(recipient)
        message.recipients = recipients

    # Set CC recipients
    if mail.cc:
        cc_recipients = message.recipients if message.recipients else []
        for cc_addr in mail.cc:
            recipient = msg.Recipient()
            recipient.display_name = cc_addr[0] if cc_addr[0] else cc_addr[1]
            recipient.email_address = cc_addr[1]
            recipient.recipient_type = msg.RecipientType.CC
            cc_recipients.append(recipient)
        message.recipients = cc_recipients

    # Set subject and body
    message.subject = mail.subject if mail.subject else ""
    
    # Use HTML body if available, otherwise plain text
    if hasattr(mail, 'text_html') and mail.text_html and len(mail.text_html) > 1:
        message.body_html = mail.text_html
    elif mail.body:
        message.body = mail.body
    
    # Handle attachments
    if mail.attachments:
        attachments = []
        for attachment_data in mail.attachments:
            attachment = msg.Attachment()
            
            # Set filename
            filename = attachment_data.get('filename', 'attachment')
            attachment.display_name = filename
            attachment.filename = filename
            
            # Set content type if available
            if 'content-type' in attachment_data:
                attachment.mime_tag = attachment_data['content-type']
            
            # Set attachment data - handle different payload formats
            if 'payload' in attachment_data:
                payload = attachment_data['payload']
                if isinstance(payload, str):
                    # Remove any whitespace/newlines and decode from base64
                    try:
                        clean_payload = payload.replace('\n', '').replace('\r', '').replace(' ', '')
                        attachment.data = base64.b64decode(clean_payload)
                        print(f"Decoded attachment {filename}: {len(attachment.data)} bytes")
                    except Exception as e:
                        print(f"Failed to decode base64 for {filename}: {e}")
                        # If base64 decode fails, encode as bytes
                        attachment.data = payload.encode('utf-8')
                elif isinstance(payload, bytes):
                    # If it's already bytes, use directly
                    attachment.data = payload
                else:
                    # Try to convert to bytes
                    attachment.data = bytes(payload)
            
            attachments.append(attachment)
        
        message.attachments = attachments
        print(f"Added {len(attachments)} attachments")
    
    # Set date
    if mail.date:
        if isinstance(mail.date, datetime):
            # Remove timezone info to avoid comparison issues
            if mail.date.tzinfo is not None:
                message.client_submit_time = mail.date.replace(tzinfo=None)
            else:
                message.client_submit_time = mail.date
        else:
            try:
                # Try to parse date string if it's not already a datetime object
                if hasattr(mail.date, 'replace') and mail.date.tzinfo is not None:
                    message.client_submit_time = mail.date.replace(tzinfo=None)
                else:
                    message.client_submit_time = mail.date
            except:
                message.client_submit_time = datetime.now()
    else:
        message.client_submit_time = datetime.now()

    # Save as .msg file
    message.save(msg_path)
    print(f"Converted {eml_path} -> {msg_path}")

def convert_directory(eml_dir, msg_dir):
    # If `eml_dir` is a file, convert that single file.
    if os.path.isfile(eml_dir):
        base = os.path.splitext(os.path.basename(eml_dir))[0]
        os.makedirs(msg_dir, exist_ok=True)
        msg_path = os.path.join(msg_dir, base + ".msg")
        eml_to_msg(eml_dir, msg_path)
        return

    # Otherwise treat `eml_dir` as a directory containing .eml files.
    os.makedirs(msg_dir, exist_ok=True)
    for filename in os.listdir(eml_dir):
        if filename.lower().endswith(".eml"):
            eml_path = os.path.join(eml_dir, filename)
            msg_path = os.path.join(msg_dir, filename.rsplit(".", 1)[0] + ".msg")
            eml_to_msg(eml_path, msg_path)

if __name__ == "__main__":
    # Example usage: build paths relative to this script so we don't try to write to '/'.
    project_root = os.path.abspath(os.path.dirname(__file__))

    eml_folder = os.path.join(project_root, "[External] Fwd_ Formal Public Comment – Opposition to the Starlight Solar Project.eml")
    msg_folder = os.path.join(project_root, "[External] CONVERTED Fwd_ Formal Public Comment – Opposition to the Starlight Solar Project.msg")

    # If the eml path points to a single .eml file, `convert_directory` will create
    # the `msg_folder` and convert that single file; if it's a directory it will
    # convert all .eml files in it.
    convert_directory(eml_folder, msg_folder)