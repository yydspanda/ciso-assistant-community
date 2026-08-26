import pytest

from iam.models import Folder


@pytest.fixture
def regulatory_root(db):
    Folder._CACHED_ROOT_FOLDER = None
    Folder._init_root_folder()
    return Folder.get_root_folder()
