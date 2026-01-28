# Task-4
#include <stdio.h>
#include <string.h>

int main() {
    char buf[8];
    gets(buf);   // DANGEROUS
    printf("%s\n", buf);
}fgets(buf, sizeof(buf), stdin);gcc -fstack-protector -D_FORTIFY_SOURCE=2 -pie -fPIE file.c-rwsr-xr-x root root /usr/bin/vulnerablechmod u-s /usr/bin/vulnerablechmod 777 script.shchmod 750 script.shsystem("ls");execl("/bin/ls", "ls", NULL);if(access("file.txt", W_OK) == 0) {
    open("file.txt", O_WRONLY);
}int fd = open("file.txt", O_WRONLY | O_CREAT | O_EXCL);password = admin123import bcrypt

bcrypt.hashpw(password, bcrypt.gensalt())systemctl disable telnetufw enable
ufw allow sshsystem("ping " . $_GET['ip']);$ip = escapeshellarg($_GET['ip']);
system("ping $ip");
