package hudson.os.windows.ManagedWindowsServiceLauncher.AccountInfo;


def f=namespace(lib.FormTagLib)
def c=namespace(lib.CredentialsTagLib)

f.entry (title:_("Credentials"), field:"credentialsId") {
    c.select()
}

