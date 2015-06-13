package hudson.os.windows.ManagedWindowsServiceAccount.AnotherUser;

def f = namespace(lib.FormTagLib)
def c=namespace(lib.CredentialsTagLib)
f.entry (title:_("Credentials"), field:"credentialsId") {
    c.select()
}