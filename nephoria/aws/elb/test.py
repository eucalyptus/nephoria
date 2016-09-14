from nephoria.testcontroller import TestController
tc = TestController(hostname="10.111.1.73", log_level='DEBUG', password='foobar')
user=tc.create_user_using_cloudadmin('ui-test-acct-03','admin')

print""
print "user.cloudformation.delete_all_stacks()"
print""
stacks=user.cloudformation.delete_all_stacks()

