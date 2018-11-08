import sys

from nativedroid.server.nativedroid_server import serve


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print 'usage: start_nativedroid_server.py binary_path native_ss_file java_ss_file'
        exit(0)
    serve(sys.argv[1], sys.argv[2], sys.argv[3])