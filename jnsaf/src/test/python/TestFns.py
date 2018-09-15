import jpy


def fn1(i):
    return i + 1


def fn2(s):
    return 'Hello, ' + s


def fn3(d):
    Data = jpy.get_type('org.argus.jnsaf.secret.Data')
    data = Data()
    data.set(d)
    return data
