import inspect
import os
import sys

# This chunk of code makes the test work when run from within VSCode
current_file = inspect.getfile(inspect.currentframe())
module_path = os.path.realpath(os.path.abspath(os.path.join(os.path.split(current_file)[0],'..')))
if module_path not in sys.path:
	sys.path.append(module_path)

import log
from serverconfig import gConfig
from workfolder import WorkFolder
from workspace import Workspace
from user import User

TEST_WID = '00000000-0000-0000-0000-000000000000'

TEST_UID_1 = '00000000-0000-0000-0000-000000000001'
TEST_UID_2 = '00000000-0000-0000-0000-000000000003'
TEST_UID_3 = '00000000-0000-0000-0000-000000000005'

TEST_DEVID_1 = '00000000-0000-0000-0000-000000000002'
TEST_DEVID_2 = '00000000-0000-0000-0000-000000000004'
TEST_DEVID_3 = '00000000-0000-0000-0000-000000000006'
TEST_DEVID_4 = '00000000-0000-0000-0000-000000000008'
TEST_DEVID_5 = '00000000-0000-0000-0000-00000000000a'

def generate_empty_test_workspace():

	# Start by generating an empty test workspace. We'll use an ID with all zeroes
	w = Workspace()
	w.reset(TEST_WID)
	w.save()
	return w

def workspace_test1():
	# Test basic workspace initialization and user adding / removing
	w = generate_empty_test_workspace()
	w.add_user(TEST_UID_1, 'admin', TEST_DEVID_1)
	w.add_user(TEST_UID_2, 'user', TEST_DEVID_2)
	w.add_user(TEST_UID_3, 'restricted', TEST_DEVID_3)
	w.remove_user(TEST_UID_3)

def workspace_test2():
	# Test workspace::load()
	w = generate_empty_test_workspace()
	w.add_user(TEST_UID_1, 'admin', TEST_DEVID_1)
	w.add_user(TEST_UID_2, 'user', TEST_DEVID_2)
	w = Workspace()
	w.load(TEST_WID)

def workfolder_test1():
	# Test workfolder::set()
	ws = generate_empty_test_workspace()
	ws.add_user(TEST_UID_1, 'admin', TEST_DEVID_1)
	wf = WorkFolder(TEST_WID)
	wf.set(aocp_path="messages")
	wf.set(aocp_path="files attachments")
	wf.set(aocp_path="calendar")
	wf.set(aocp_path="contacts")
	wf.set(aocp_path="extensions")
	wf.set(aocp_path="notes")
	wf.set(aocp_path="social")
	wf.set(aocp_path="tasks")
	# workfolder::open
	wf.open(TEST_WID, 'files')
	

def RunTests():
	#workspace_test1()
	#workspace_test2()
	workfolder_test1()

if __name__ == '__main__':
	log.Init('testlog.log')
	RunTests()
