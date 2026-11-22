"""Importers that turn real infrastructure descriptions into the normalized configuration JSON.

Every importer produces the same JSON the upload endpoint accepts, so the result goes through the
one validator (``domain/network/schema.py``) and nothing downstream knows where it came from:

* ``terraform``       ``terraform show -json`` of a plan or of a state
* ``cloudformation``  a CloudFormation template (JSON or YAML)
* ``aws_describe``    boto3 ``Describe*`` responses (the live, read-only AWS import)

What an importer cannot represent is never guessed: it is dropped and reported in ``warnings``.
"""

from domain.network.importers.builder import ConfigBuilder, ImporterError, ImportReport

__all__ = ["ConfigBuilder", "ImportReport", "ImporterError"]
