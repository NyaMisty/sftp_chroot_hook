gcc -fPIC -shared -fvisibility=hidden sftp_chroot.c -ldl -lcap -fcf-protection=none -o sftp_chroot.so
