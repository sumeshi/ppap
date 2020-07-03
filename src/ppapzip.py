# coding: utf-8
import shutil
import argparse
import traceback
from typing import List
from pathlib import Path
from datetime import datetime

import pyminizip

from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


def get_now() -> str:
    now = datetime.now()
    return now.strftime("%Y%m%d_%H%M%S%f")


def load_key(filepath: Path, passphrase: str = ""):
    return RSA.importKey(filepath.read_text(), passphrase=passphrase)


def encrypt_pass(passphrase: str, key: RsaKey) -> bytes:
    public_cipher = PKCS1_OAEP.new(key)
    return public_cipher.encrypt(passphrase.encode())


def decrypt_pass(passphrase: bytes, key: RsaKey) -> str:
    private_cipher = PKCS1_OAEP.new(key)
    return private_cipher.decrypt(passphrase).decode()


def encrypt(filepath_list: List[str], key_path: str, now: str, output_path: str = None):
    current = Path(".").resolve()

    # generate encrypted_key
    zipkey = get_random_bytes(128).hex()
    crypted = encrypt_pass(zipkey, load_key(Path(key_path)))

    try:
        # create tarball
        tempdir = Path(current, f"temp-ppap-{get_now()}").resolve()
        tarball_path = compress_contents(filepath_list, tempdir)

        # zip with passphrase
        pyminizip.compress(
            str(tarball_path),
            None,
            str(tempdir / Path("ppap_encrypted_contents.zip")),
            zipkey,
            4,
        )

        # delete original contents
        tarball_path.unlink()

        # copy encrypted key
        encrypted_key_path = tempdir / Path(".encrypted_key")
        encrypted_key_path.write_text(crypted.hex())

        if output_path:
            if Path(output_path).is_dir():
                dest = Path(output_path, f"ppap-{get_now()}").resolve()
            else:
                dest = Path(output_path)
        else:
            dest = Path(tempdir.parent, f"ppap-{get_now()}").resolve()

        # compress all files
        shutil.make_archive(str(dest), "zip", root_dir=tempdir)

    except Exception:
        traceback.print_exc()

    finally:
        # remove tempdir
        shutil.rmtree(tempdir)


def compress_contents(filepath_list: List[str], tempdir: Path) -> Path:
    # create tarball
    tempdir.mkdir()
    for filepath in filepath_list:
        if Path(filepath).exists():
            if Path(filepath).is_dir():
                dest_path = Path(tempdir, Path(filepath).name)
                shutil.copytree(filepath, str(dest_path))
            else:
                dest_path = Path(
                    tempdir, Path(filepath).parent.name, Path(filepath).name
                )
                shutil.copy(filepath, str(dest_path))
        else:
            print(f"{filepath}: File or Directory not found. ")

    tarball_path = tempdir / Path("ppap_contents")
    shutil.make_archive(str(tarball_path), "tar", root_dir=tempdir)

    # remove files
    for file in tempdir.glob("**/*"):
        if not file.name == tarball_path.with_suffix(".tar").name:
            if file.is_dir():
                shutil.rmtree(str(file))
            else:
                file.unlink()

    return tarball_path.with_suffix(".tar")


def decrypt(file_path: str, key_path: str, passphrase: str, output_path: str = None):
    current = Path(".").resolve()
    try:
        # unpack
        tempdir = Path(current, f"temp-ppap-{get_now()}").resolve()
        shutil.unpack_archive(file_path, str(tempdir), "zip")

        # decrypt key
        encrypted_key = tempdir / Path(".encrypted_key")
        decrypted_key = decrypt_pass(
            bytes.fromhex(encrypted_key.read_text()),
            load_key(Path(key_path), passphrase=passphrase),
        )

        # decrypt file
        encrypted_contents = tempdir / Path("ppap_encrypted_contents.zip")
        pyminizip.uncompress(
            str(encrypted_contents), decrypted_key, str(tempdir), int(),
        )

        decrypted_contents = tempdir / Path("ppap_contents.tar")

        if output_path:
            if Path(output_path).resolve().is_dir():
                dest = Path(tempdir.parent, f"ppap-{get_now()}").resolve()
            else:
                dest = Path(current, output_path).resolve()
        else:
            dest = Path(tempdir.parent, f"ppap-{get_now()}").resolve()

        shutil.unpack_archive(
            str(decrypted_contents), dest, "tar",
        )

    except Exception:
        traceback.print_exc()

    finally:
        # remove tempdir
        shutil.rmtree(tempdir)


def ppap():
    parser = argparse.ArgumentParser(description="PPAP")
    parser.add_argument("filepath_list", nargs="+", help="Input Path")
    parser.add_argument("--out", "-o", type=str, default="", help="Destination Path")
    parser.add_argument("--key", required=True, help="Public/Private key file(RSA).")

    # encrypt
    parser.add_argument("--encrypt", "-e", action="store_true", help="Encryption flag")

    # decrypt
    parser.add_argument("--decrypt", "-d", action="store_true", help="Decryption flag")
    parser.add_argument(
        "--passphrase",
        "-p",
        type=str,
        default="",
        help="If using passphrase your private key",
    )
    args = parser.parse_args()

    try:
        if not args.encrypt and not args.decrypt:
            raise Exception("Exception: --encrypt or --decrypt option is required.")

        if not args.encrypt ^ args.decrypt:
            raise Exception(
                "Exception: --encrypt and --decrypt options cannot be used together."
            )

        if args.encrypt:
            encrypt(args.filepath_list, args.key, now=get_now(), output_path=args.out)
        else:
            if len(args.filepath_list) == 1:
                decrypt(
                    args.filepath_list[0],
                    args.key,
                    passphrase=args.passphrase,
                    output_path=args.out,
                )
            else:
                raise Exception(
                    "Exception: Only one file can be selected for decryption."
                )

    except Exception as e:
        print(e)


if __name__ == "__main__":
    ppap()
