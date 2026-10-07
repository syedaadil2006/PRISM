# Live feed folder

PRISM tails every *.jsonl, *.ndjson, *.log and *.csv file in this folder while it runs:
lines appended to them are ingested within about a second. Point a log shipper here, or
append records by hand. Files whose name starts with "_" are ignored. Contents are not
committed to git.
