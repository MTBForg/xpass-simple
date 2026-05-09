import os
from app import app, db, User, Folder, SharedFolder, Credential
from create_admin import create_admin
import traceback

with app.app_context():
    try:
        db.drop_all()
        # DB is created automatically due to the code at the bottom of app.py
        db.create_all()
        print("Database initialized.")

        from app import setup_user_keys
        
        user1_keys = setup_user_keys("password123")
        u1 = User(username="user1", email="user1@test.com", role="user", **user1_keys)
        db.session.add(u1)
        
        user2_keys = setup_user_keys("password123")
        u2 = User(username="user2", email="user2@test.com", role="user", **user2_keys)
        db.session.add(u2)
        
        db.session.commit()
        print("Users created.")
        
        from crypto import generate_folder_key, encrypt_folder_key, decrypt_user_key, derive_master_key
        
        # Simulate User 1 login
        u1_master = derive_master_key("password123", u1.user_key_salt, u1.user_key_iterations)
        u1_uek = decrypt_user_key(u1.encrypted_user_key, u1_master)
        
        f1_key = generate_folder_key()
        f1 = Folder(name="My Folder", user_id=u1.id, encrypted_folder_key=encrypt_folder_key(f1_key, u1_uek))
        db.session.add(f1)
        db.session.commit()
        print("Folder created.")
        
        # Add credential
        from crypto import encrypt_credential, decrypt_credential
        c1 = Credential(folder_id=f1.id, user_id=u1.id, name="Test", url="http", username="test", password=encrypt_credential("secretpass", f1_key))
        db.session.add(c1)
        db.session.commit()
        
        # Test Decryption
        decrypted = decrypt_credential(c1.password, f1_key)
        assert decrypted == "secretpass"
        print("Credential encrypted/decrypted successfully!")
        
        # Test Sharing
        from crypto import wrap_folder_key_for_recipient, unwrap_folder_key, decrypt_private_key
        envelope = wrap_folder_key_for_recipient(f1_key, u2.rsa_public_key.encode())
        shared = SharedFolder(folder_id=f1.id, shared_with_user_id=u2.id, encrypted_folder_key_envelope=envelope)
        db.session.add(shared)
        db.session.commit()
        
        # Simulate User 2 access
        u2_master = derive_master_key("password123", u2.user_key_salt, u2.user_key_iterations)
        u2_uek = decrypt_user_key(u2.encrypted_user_key, u2_master)
        u2_priv_pem = decrypt_private_key(u2.encrypted_rsa_private_key, u2_master)
        
        # User 2 unwraps folder key
        u2_unwrapped_f1_key = unwrap_folder_key(shared.encrypted_folder_key_envelope, u2_priv_pem)
        
        assert u2_unwrapped_f1_key == f1_key
        print("Folder key shared and unwrapped successfully!")
        
        # User 2 decrypts the credential
        u2_decrypted_pass = decrypt_credential(c1.password, u2_unwrapped_f1_key)
        assert u2_decrypted_pass == "secretpass"
        print("User 2 successfully decrypted shared credential!")
        
        print("\nAll cryptography tests passed! Zero Knowledge Architecture is working perfectly.")
        
    except Exception as e:
        print("Test failed:")
        traceback.print_exc()
