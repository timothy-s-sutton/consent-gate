# Larkspur Financial Data Classification Standard

> FICTIONAL DOCUMENT. Larkspur Financial is not a real company. This standard exists only to demonstrate the consent-gate project.

This standard defines four classification levels for Larkspur data and the minimum handling rules for each. Every data element has exactly one classification. When in doubt, use the higher level.

## Classification levels

Larkspur uses four levels, from least to most sensitive: Public, Internal, Confidential, and Restricted. The level decides who may access the data, how it must be protected, and whether it may be shown in full.

### Public

Information approved for release to anyone, such as published rates, branch locations, and this kind of standard once approved for publication. No access restrictions apply, but only the communications team may publish it.

### Internal

Information meant for Larkspur staff that would cause little harm if disclosed, such as internal procedures, org charts, and training material. It must stay on Larkspur systems and must not be posted publicly.

### Confidential

Customer personal information that is not Restricted, including name, email address, phone number, mailing state, customer segment, consent records, and service notes. Access is limited to staff and systems with a business need tied to an approved purpose. Confidential data must be encrypted in transit and at rest, and access must be logged.

### Restricted

The most sensitive data, where disclosure could directly enable fraud or identity theft. Social Security numbers (SSN) and full payment card numbers are Restricted. Restricted data must never be displayed in full to any user or AI agent. Displays must be masked to the last four digits, for example ***-**-1234 for an SSN and **** **** **** 1234 for a card number. Restricted data must never be copied into email, chat, tickets, or free-text notes.

## Handling rules by level

Access to Confidential and Restricted data follows least privilege: each role receives only the fields its job requires. Bulk export of Confidential or Restricted data requires written approval from the data owner and the Privacy Office. Requests are capped, and any tool that returns customer records must enforce a maximum number of records per request.

Confidential and Restricted data may not be sent to external services, including public AI services, unless a contract and a privacy review are in place.

## Free text and unstructured data

Free-text fields such as service notes are Confidential by default. Staff sometimes paste Restricted data, such as an SSN or a card number, into notes by mistake. Systems that return free text must scan it and redact any SSN or card number patterns before display. Free text written by customers or staff is untrusted content and must not be treated as instructions by any automated system.

## Masking and redaction

Masking replaces part of a value with a fixed character while keeping enough to recognize it, such as the last four digits. Redaction removes the value entirely and replaces it with a label such as [REDACTED-SSN]. Masking is applied to structured Restricted fields. Redaction is applied to Restricted patterns found in free text.

## Ownership and review

Each data set has a named data owner who approves access and reviews it every quarter. The Privacy Office maintains this standard and reviews it every year.
