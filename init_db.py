# init_db.py
import os
from rbac import init_db, add_user
from key_management import generate_rsa_keypair
from integrity import generate_hmac_key

def seed():
    print("Initializing database and keys...")
    init_db()

    # Generate RSA keys (if not present)
    try:
        generate_rsa_keypair(overwrite=False)
        print("RSA keypair created in 'keys/' (or already exists).")
    except FileExistsError:
        print("RSA keypair already exists; skipping generation.")

    # Create sample users with YOUR names
    try:
        add_user("meenakshi", "adminpass123", role="admin")
        add_user("A", "editorpass123", role="editor")
        add_user("B", "viewerpass123", role="viewer")

        print("Sample users created: meenakshi (admin), A (editor), B (viewer)")
    except Exception as e:
        print("Could not add users (maybe they already exist):", e)

    # Create HMAC key
    if not os.path.exists("hmac.key"):
        with open("hmac.key", "wb") as f:
            f.write(generate_hmac_key())
        print("Created new hmac.key")
    else:
        print("hmac.key already exists")

if __name__ == "__main__":
    seed()