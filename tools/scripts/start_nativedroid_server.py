import sys

from nativedroid.server.nativedroid_server import serve


if __name__ == '__main__':
    if len(sys.argv) != 8:
        print 'usage: start_nativedroid_server.py binary_path address port jnsaf_address jnsaf_port native_ss_file java_ss_file'
        exit(0)
    serve(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7])
