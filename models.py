import re
import os
from typing import List, Optional
from pydantic import BaseModel, field_validator

# Maximum recipients per request (SendGrid limit is 1000 per API call)
MAX_RECIPIENTS = int(os.getenv("MAX_RECIPIENTS", "500"))

# Email regex pattern for validation
# Uses atom(.atom)* pattern to prevent leading/trailing/consecutive dots,
# and label(.label)+ for domain to prevent leading/trailing hyphens
EMAIL_REGEX = re.compile(
    r'^[a-zA-Z0-9_%+-]+'          # first atom in local part
    r'(?:\.[a-zA-Z0-9_%+-]+)*'    # (.atom)* — no consecutive dots possible
    r'@'
    r'(?:[a-zA-Z0-9]'             # each domain label starts with alnum
    r'(?:[a-zA-Z0-9-]*'           # middle can include hyphens
    r'[a-zA-Z0-9])?\.)+'          # ends with alnum, followed by dot
    r'[a-zA-Z]{2,}$'              # TLD: 2+ alpha chars
)


class EmailRequest(BaseModel):
    to_list: List[str]
    cc_list: Optional[List[str]] = None
    mail_body: str

    @field_validator('to_list')
    @classmethod
    def validate_to_list(cls, v):
        if not v:
            raise ValueError('to_list cannot be empty')
        if len(v) > MAX_RECIPIENTS:
            raise ValueError(f'to_list exceeds maximum of {MAX_RECIPIENTS} recipients')
        for email in v:
            if not EMAIL_REGEX.match(email):
                raise ValueError(f'Invalid email address: {email}')
        return v

    @field_validator('cc_list')
    @classmethod
    def validate_cc_list(cls, v):
        if v:
            if len(v) > MAX_RECIPIENTS:
                raise ValueError(f'cc_list exceeds maximum of {MAX_RECIPIENTS} recipients')
            for email in v:
                if not EMAIL_REGEX.match(email):
                    raise ValueError(f'Invalid email address: {email}')
        return v

    @field_validator('mail_body')
    @classmethod
    def validate_mail_body(cls, v):
        if not v or not v.strip():
            raise ValueError('mail_body cannot be empty')
        return v
