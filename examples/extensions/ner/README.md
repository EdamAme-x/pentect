# NER extension

External NER belongs outside core.

Expected shape:

- agent hook or wrapper calls a local NER process
- output is converted to Pentect spans
- raw values stay local
- masked output returns through Pentect

Do not promote generated NER results into built-in regex rules.
