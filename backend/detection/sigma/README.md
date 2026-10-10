# PRISM's bundled Sigma rules

Original rules written for PRISM in the [Sigma](https://sigmahq.io) format. They cover techniques that
PRISM's built-in rules (backend/app/engine/mitre.py) do not, such as shadow-copy deletion,
persistence through scheduled tasks and services, and signed-binary proxy execution.

Add more rules - your own, or a checkout of the SigmaHQ repository - by listing their folders in
`PRISM_DETECTION_SIGMA_DIRS` (a JSON list). Rules PRISM cannot evaluate are skipped and listed at
`GET /api/detection`.
