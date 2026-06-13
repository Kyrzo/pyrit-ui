#!/usr/bin/env python3
"""
PyRIT UI — User Management CLI
================================

QUICK START (interactive, no flags needed):
    python3 create_user.py

COMMANDS:
    python3 create_user.py create     --username admin --password secret --role admin
    python3 create_user.py list
    python3 create_user.py update     --username user1 --role analyst
    python3 create_user.py activate   --username user1
    python3 create_user.py deactivate --username user1
    python3 create_user.py delete     --username user1
    python3 create_user.py passwd     --username user1 --password newpass
"""
import argparse, getpass, os, sys
from dotenv import load_dotenv
load_dotenv()
from auth import init_db, create_user, list_users, update_user, delete_user, change_password

ROLES = ["admin", "analyst", "viewer"]
ROLE_DESC = {
    "admin":   "Full access — manage users, launch scans, view all results",
    "analyst": "Launch scans, view own results, export reports",
    "viewer":  "Read-only — view dashboard and results only",
}

def cyan(s): return f"\033[36m{s}\033[0m"
def green(s): return f"\033[32m{s}\033[0m"
def red(s): return f"\033[31m{s}\033[0m"
def yellow(s): return f"\033[33m{s}\033[0m"

def print_header():
    print(f"\n{cyan('╔══════════════════════════════════════╗')}")
    print(f"{cyan('║       PyRIT UI — User Manager       ║')}")
    print(f"{cyan('╚══════════════════════════════════════╝')}\n")

def print_table(users):
    if not users:
        print(yellow("  No users found.\n")); return
    print(f"\n  {'ID':<4} {'Username':<20} {'Role':<10} {'Active':<8} {'Last login':<22} {'Created'}")
    print("  " + "─" * 78)
    for u in users:
        a = green("✓") if u["active"] else red("✗")
        last = u["last_login"][:19].replace("T"," ") if u["last_login"] else "never"
        rc = red if u["role"]=="admin" else cyan if u["role"]=="analyst" else lambda x: x
        print(f"  {u['id']:<4} {u['username']:<20} {rc(u['role']):<10}  {a}       {last:<22} {u['created_at'][:10]}")
    print()

def interactive():
    print_header()
    init_db()
    while True:
        print("  What do you want to do?\n")
        print(f"  {cyan('1')}  Create a new user")
        print(f"  {cyan('2')}  List all users")
        print(f"  {cyan('3')}  Edit a user (role / status)")
        print(f"  {cyan('4')}  Change a user's password")
        print(f"  {cyan('5')}  Delete a user")
        print(f"  {cyan('0')}  Exit\n")
        choice = input("  Enter option: ").strip()
        print()

        if choice == "0":
            print("  Bye!\n"); break

        elif choice == "1":
            print(f"  {cyan('── Create new user ──')}\n")
            username = input("  Username: ").strip()
            if not username: print(red("  ✗ Username required.\n")); continue
            password = getpass.getpass("  Password (hidden, min 8 chars): ")
            if len(password) < 8: print(red("  ✗ Password too short.\n")); continue
            confirm = getpass.getpass("  Confirm password: ")
            if password != confirm: print(red("  ✗ Passwords do not match.\n")); continue
            print()
            for i, r in enumerate(ROLES, 1):
                print(f"  {cyan(i)}  {r:<10} — {ROLE_DESC[r]}")
            rc = input("\n  Select role [1/2/3] (default 3=viewer): ").strip() or "3"
            try: role = ROLES[int(rc)-1]
            except: print(red("  ✗ Invalid choice.\n")); continue
            try:
                u = create_user(username, password, role)
                print(green(f"\n  ✓ User created: {u['username']} (role: {u['role']})\n"))
            except ValueError as e:
                print(red(f"  ✗ {e}\n"))

        elif choice == "2":
            print_table(list_users())

        elif choice == "3":
            print(f"  {cyan('── Edit user ──')}\n")
            print_table(list_users())
            username = input("  Username to edit: ").strip()
            if not username: continue
            print()
            for i, r in enumerate(ROLES, 1):
                print(f"  {cyan(i)}  {r:<10} — {ROLE_DESC[r]}")
            print(f"  {cyan(4)}  Keep current role")
            rc = input("\n  New role [1-4]: ").strip()
            new_role = ROLES[int(rc)-1] if rc in ("1","2","3") else None
            sc = input("  Status: [1] Active  [2] Inactive  [3] Keep current: ").strip()
            new_active = True if sc=="1" else False if sc=="2" else None
            u = update_user(username, role=new_role, active=new_active)
            if u: print(green(f"\n  ✓ Updated: {u['username']} — role: {u['role']}, active: {bool(u['active'])}\n"))
            else: print(red(f"  ✗ User not found: {username}\n"))

        elif choice == "4":
            print(f"  {cyan('── Change password ──')}\n")
            username = input("  Username: ").strip()
            pw = getpass.getpass("  New password (hidden, min 8 chars): ")
            if len(pw) < 8: print(red("  ✗ Password too short.\n")); continue
            cf = getpass.getpass("  Confirm: ")
            if pw != cf: print(red("  ✗ Passwords do not match.\n")); continue
            if change_password(username, pw): print(green(f"\n  ✓ Password changed: {username}\n"))
            else: print(red(f"  ✗ User not found: {username}\n"))

        elif choice == "5":
            print(f"  {cyan('── Delete user ──')}\n")
            print_table(list_users())
            username = input("  Username to delete: ").strip()
            if not username: continue
            cf = input(red(f"  Are you sure you want to delete '{username}'? [y/N]: ")).strip().lower()
            if cf != "y": print("  Cancelled.\n"); continue
            if delete_user(username): print(green(f"\n  ✓ Deleted: {username}\n"))
            else: print(red(f"  ✗ User not found: {username}\n"))

        else:
            print(yellow("  ⚠ Invalid option.\n"))

def main():
    if len(sys.argv) == 1:
        interactive(); return

    parser = argparse.ArgumentParser(description="PyRIT UI User Management")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("create"); p.add_argument("--username",required=True); p.add_argument("--password",required=True); p.add_argument("--role",choices=ROLES,default="viewer")
    sub.add_parser("list")
    p = sub.add_parser("update"); p.add_argument("--username",required=True); p.add_argument("--role",choices=ROLES); p.add_argument("--active",choices=["true","false"])
    p = sub.add_parser("activate"); p.add_argument("--username",required=True)
    p = sub.add_parser("deactivate"); p.add_argument("--username",required=True)
    p = sub.add_parser("delete"); p.add_argument("--username",required=True); p.add_argument("--force",action="store_true")
    p = sub.add_parser("passwd"); p.add_argument("--username",required=True); p.add_argument("--password",required=True)

    args = parser.parse_args()
    init_db()

    if args.command == "create":
        try: u = create_user(args.username, args.password, args.role); print(green(f"✓ User created: {u['username']} (role: {u['role']})"))
        except ValueError as e: print(red(f"✗ {e}"),file=sys.stderr); sys.exit(1)
    elif args.command == "list": print_table(list_users())
    elif args.command == "update":
        active = None if not args.active else args.active=="true"
        u = update_user(args.username, role=args.role, active=active)
        if u: print(green(f"✓ Updated: {u['username']} (role:{u['role']}, active:{bool(u['active'])})"))
        else: print(red(f"✗ Not found: {args.username}"),file=sys.stderr); sys.exit(1)
    elif args.command == "activate":
        u = update_user(args.username, active=True)
        if u: print(green(f"✓ Activated: {u['username']}"))
        else: print(red(f"✗ Not found"),file=sys.stderr); sys.exit(1)
    elif args.command == "deactivate":
        u = update_user(args.username, active=False)
        if u: print(green(f"✓ Deactivated: {u['username']}"))
        else: print(red(f"✗ Not found"),file=sys.stderr); sys.exit(1)
    elif args.command == "delete":
        if not args.force and input(f"Delete '{args.username}'? [y/N]: ").lower() != "y": print("Cancelled."); return
        if delete_user(args.username): print(green(f"✓ Deleted: {args.username}"))
        else: print(red(f"✗ Not found"),file=sys.stderr); sys.exit(1)
    elif args.command == "passwd":
        if change_password(args.username, args.password): print(green(f"✓ Password changed: {args.username}"))
        else: print(red(f"✗ Not found"),file=sys.stderr); sys.exit(1)
    else: parser.print_help()

if __name__ == "__main__":
    main()
