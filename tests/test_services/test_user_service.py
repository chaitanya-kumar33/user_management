from builtins import range
import pytest
from sqlalchemy import select
from app.dependencies import get_settings
from app.models.user_model import User, UserRole
from app.services.user_service import UserService
from app.utils.nickname_gen import generate_nickname
from datetime import datetime, timedelta, timezone

pytestmark = pytest.mark.asyncio

# Test creating a user with valid data
async def test_create_user_with_valid_data(db_session, email_service):
    user_data = {
        "nickname": generate_nickname(),
        "email": "valid_user@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ADMIN.name
    }
    user = await UserService.create(db_session, user_data, email_service)
    assert user is not None
    assert user.email == user_data["email"]

# Test creating a user with invalid data
async def test_create_user_with_invalid_data(db_session, email_service):
    user_data = {
        "nickname": "",  # Invalid nickname
        "email": "invalidemail",  # Invalid email
        "password": "short",  # Invalid password
    }
    user = await UserService.create(db_session, user_data, email_service)
    assert user is None

# Test fetching a user by ID when the user exists
async def test_get_by_id_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_id(db_session, user.id)
    assert retrieved_user.id == user.id

# Test fetching a user by ID when the user does not exist
async def test_get_by_id_user_does_not_exist(db_session):
    non_existent_user_id = "non-existent-id"
    retrieved_user = await UserService.get_by_id(db_session, non_existent_user_id)
    assert retrieved_user is None

# Test fetching a user by nickname when the user exists
async def test_get_by_nickname_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_nickname(db_session, user.nickname)
    assert retrieved_user.nickname == user.nickname

# Test fetching a user by nickname when the user does not exist
async def test_get_by_nickname_user_does_not_exist(db_session):
    retrieved_user = await UserService.get_by_nickname(db_session, "non_existent_nickname")
    assert retrieved_user is None

# Test fetching a user by email when the user exists
async def test_get_by_email_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_email(db_session, user.email)
    assert retrieved_user.email == user.email

# Test fetching a user by email when the user does not exist
async def test_get_by_email_user_does_not_exist(db_session):
    retrieved_user = await UserService.get_by_email(db_session, "non_existent_email@example.com")
    assert retrieved_user is None

# Test updating a user with valid data
async def test_update_user_valid_data(db_session, user):
    new_email = "updated_email@example.com"
    updated_user = await UserService.update(db_session, user.id, {"email": new_email})
    assert updated_user is not None
    assert updated_user.email == new_email

# Test updating a user with invalid data
async def test_update_user_invalid_data(db_session, user):
    updated_user = await UserService.update(db_session, user.id, {"email": "invalidemail"})
    assert updated_user is None

# Test deleting a user who exists
async def test_delete_user_exists(db_session, user):
    deletion_success = await UserService.delete(db_session, user.id)
    assert deletion_success is True

# Test attempting to delete a user who does not exist
async def test_delete_user_does_not_exist(db_session):
    non_existent_user_id = "non-existent-id"
    deletion_success = await UserService.delete(db_session, non_existent_user_id)
    assert deletion_success is False

# Test listing users with pagination
async def test_list_users_with_pagination(db_session, users_with_same_role_50_users):
    users_page_1 = await UserService.list_users(db_session, skip=0, limit=10)
    users_page_2 = await UserService.list_users(db_session, skip=10, limit=10)
    assert len(users_page_1) == 10
    assert len(users_page_2) == 10
    assert users_page_1[0].id != users_page_2[0].id

# Test registering a user with valid data
async def test_register_user_with_valid_data(db_session, email_service):
    user_data = {
        "nickname": generate_nickname(),
        "email": "register_valid_user@example.com",
        "password": "RegisterValid123!",
        "role": UserRole.ADMIN
    }
    user = await UserService.register_user(db_session, user_data, email_service)
    assert user is not None
    assert user.email == user_data["email"]

# Test attempting to register a user with invalid data
async def test_register_user_with_invalid_data(db_session, email_service):
    user_data = {
        "email": "registerinvalidemail",  # Invalid email
        "password": "short",  # Invalid password
    }
    user = await UserService.register_user(db_session, user_data, email_service)
    assert user is None

# Test successful user login
async def test_login_user_successful(db_session, verified_user):
    user_data = {
        "email": verified_user.email,
        "password": "MySuperPassword$1234",
    }
    logged_in_user = await UserService.login_user(db_session, user_data["email"], user_data["password"])
    assert logged_in_user is not None

# Test user login with incorrect email
async def test_login_user_incorrect_email(db_session):
    user = await UserService.login_user(db_session, "nonexistentuser@noway.com", "Password123!")
    assert user is None

# Test user login with incorrect password
async def test_login_user_incorrect_password(db_session, user):
    user = await UserService.login_user(db_session, user.email, "IncorrectPassword!")
    assert user is None

# Test account lock after maximum failed login attempts
async def test_account_lock_after_failed_logins(db_session, verified_user):
    max_login_attempts = get_settings().max_login_attempts
    for _ in range(max_login_attempts):
        await UserService.login_user(db_session, verified_user.email, "wrongpassword")
    
    is_locked = await UserService.is_account_locked(db_session, verified_user.email)
    assert is_locked, "The account should be locked after the maximum number of failed login attempts."

# Test resetting a user's password
async def test_reset_password(db_session, user):
    new_password = "NewPassword123!"
    reset_success = await UserService.reset_password(db_session, user.id, new_password)
    assert reset_success is True

# Test verifying a user's email
async def test_verify_email_with_token(db_session, user):
    token = "valid_token_example"  # This should be set in your user setup if it depends on a real token
    user.verification_token = token  # Simulating setting the token in the database
    await db_session.commit()
    result = await UserService.verify_email_with_token(db_session, user.id, token)
    assert result is True

# Test unlocking a user's account
async def test_unlock_user_account(db_session, locked_user):
    unlocked = await UserService.unlock_user_account(db_session, locked_user.id)
    assert unlocked, "The account should be unlocked"
    refreshed_user = await UserService.get_by_id(db_session, locked_user.id)
    assert not refreshed_user.is_locked, "The user should no longer be locked"

# Test creating a user and verifying additional fields
async def test_create_user_with_additional_fields(db_session, email_service):
    user_data = {
        "nickname": generate_nickname(),
        "email": "additional_fields_user@example.com",
        "password": "ValidPassword123!",
        "role": "ANONYMOUS",
        "is_professional": True,
        "linkedin_profile_url": "https://www.linkedin.com/in/testuser",
        "github_profile_url": "https://github.com/testuser"
    }
    created_user = await UserService.create(db_session, user_data, email_service)
    
    assert created_user is not None
    assert created_user.email == user_data["email"]
    assert created_user.linkedin_profile_url == user_data["linkedin_profile_url"]
    assert created_user.github_profile_url == user_data["github_profile_url"]

# Test getting a user by nickname when the user exists (Admin Access)
async def test_get_user_by_nickname_exists(db_session, email_service, async_client, admin_token):
    
    # Create an anonymous user to be fetched
    user_data = {
        "nickname": generate_nickname(),
        "email": "valid_user@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name
    }

    # Create the anonymous user in the database using the UserService
    user = await UserService.create(db_session, user_data, email_service)

    # Attempt to fetch the user by nickname using the admin token
    response = await async_client.get(
        f"/users/nickname/{user.nickname}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    # Asserting responses
    retrieved_user = response.json()
    assert retrieved_user is not None
    assert retrieved_user["nickname"] == user.nickname

# Test unauthorized access by manager for nickname endpoint
async def test_get_user_by_nickname_unauthorized(db_session, email_service, async_client, manager_token):
    
    # Create an anonymous user to be fetched
    anonymous_data = {
        "nickname": generate_nickname(),
        "email": "anonymous_user@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name
    }

    # Create the anonymous user in the database using the UserService
    anonymous_user = await UserService.create(db_session, anonymous_data, email_service)

    # Attempt to fetch the user by nickname using the admin token
    response = await async_client.get(
        f"/users/nickname/{anonymous_user.nickname}",
        headers={"Authorization": f"Bearer {manager_token}"}
    )

    # Asserting responses
    assert response.json()["detail"] == "Operation not permitted"

# Test fetching a user by nickname when the user does not exist
async def test_get_user_by_nickname_does_not_exist(async_client, admin_token):
    
    non_existent_nickname = "non_existent_nickname"
    
    # Attempt to fetch the non-existing user by nickname using the admin token
    response = await async_client.get(
        f"/users/nickname/{non_existent_nickname}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    # Asserting responses
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"


# Test fetching a user by email when the user exists (Admin Access)
async def test_get_user_by_email_exists(db_session, email_service, async_client, admin_token):
    
    # Create an anonymous user to be fetched
    user_data = {
        "nickname": generate_nickname(),
        "email": "valid_user@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name
    }

    # Create the anonymous user in the database using the UserService
    user = await UserService.create(db_session, user_data, email_service)

    # Attempt to fetch the user by email using the admin token
    response = await async_client.get(
        f"/users/email/{user.email}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    # Asserting responses
    retrieved_user = response.json()
    assert retrieved_user is not None
    assert retrieved_user["email"] == user.email


# Test unauthorized access by manager for email endpoint
async def test_get_user_by_email_unauthorized(db_session, email_service, async_client, manager_token):
    
    # Create an anonymous user to be fetched
    anonymous_data = {
        "nickname": generate_nickname(),
        "email": "anonymous_user@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name
    }
        
    # Create the anonymous user in the database using the UserService
    anonymous_user = await UserService.create(db_session, anonymous_data, email_service)

    # Attempt to fetch the user by email using the admin token
    response = await async_client.get(
        f"/users/email/{anonymous_user.email}",
        headers={"Authorization": f"Bearer {manager_token}"}
    )

    # Asserting responses
    assert response.json()["detail"] == "Operation not permitted"


# Test fetching a user by email when the user does not exist
async def test_get_user_by_email_does_not_exist(async_client, admin_token):

    non_existent_email = "non_existent_email@example.com"
    
    # Attempt to fetch the non-existing user by email using the admin token
    response = await async_client.get(
        f"/users/email/{non_existent_email}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

# Test fetching users by role when users exist (Admin Access)
async def test_get_users_by_role_exists(db_session, email_service, async_client, admin_token):
    # Create users with the default role (ANONYMOUS)
    user_data_1 = {
        "nickname": generate_nickname(),
        "email": "authenticated_user1@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name
    }

    user_data_2 = {
        "nickname": generate_nickname(),
        "email": "authenticated_user2@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name
    }

    # Create the users in the database using the UserService
    user1 = await UserService.create(db_session, user_data_1, email_service)
    user2 = await UserService.create(db_session, user_data_2, email_service)

    # Attempt to fetch users by role using the admin token
    response = await async_client.get(
        "/users/role/ANONYMOUS?skip=0&limit=10",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    # Print the response JSON for debugging
    retrieved_users = response.json()  
    assert retrieved_users is not None
    assert retrieved_users["total"] == 2
    assert retrieved_users["page"] == 1
    assert retrieved_users["size"] == 2
    assert retrieved_users["total_pages"] == 1
    assert any(user["email"] == "authenticated_user1@example.com" for user in retrieved_users["items"])
    assert any(user["email"] == "authenticated_user2@example.com" for user in retrieved_users["items"])

# Test unauthorized access by manager for role endpoint
async def test_get_users_by_role_unauthorized(db_session, email_service, async_client, manager_token):
    # Create users with the default role (ANONYMOUS)
    user_data_1 = {
        "nickname": generate_nickname(),
        "email": "authenticated_user1@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name
    }

    user_data_2 = {
        "nickname": generate_nickname(),
        "email": "authenticated_user2@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name
    }

    # Create the users in the database using the UserService
    await UserService.create(db_session, user_data_1, email_service)
    await UserService.create(db_session, user_data_2, email_service)

    # Attempt to fetch users by role using the manager token
    response = await async_client.get(
        "/users/role/ANONYMOUS?skip=0&limit=10",
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    
    # Asserting responses
    assert response.status_code == 403
    assert response.json()["detail"] == "Operation not permitted"

# Test fetching users by role when the role does not exist
async def test_get_users_by_role_not_found(async_client, admin_token):
    non_existent_role = "NONEXISTENTROLE"

    # Attempt to fetch users by a non-existent role using the admin token
    response = await async_client.get(
        f"/users/role/{non_existent_role}?skip=0&limit=10",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid user role provided"

# Test fetching users by role when no users are found for the given role (Admin Access)
async def test_get_users_by_role_no_users_found(db_session, email_service, async_client, admin_token):
    # Create a user with a different role to ensure no users with the given role
    user_data = {
        "nickname": generate_nickname(),
        "email": "admin_user@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ADMIN.name
    }

    # Create the user in the database using the UserService
    await UserService.create(db_session, user_data, email_service)

    # Attempt to fetch users by a role that has no users (e.g., AUTHENTICATED)
    response = await async_client.get(
        "/users/role/AUTHENTICATED?skip=0&limit=10",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    # Asserting responses
    assert response.status_code == 404
    assert response.json()["detail"] == "No users with this role"

# Test pagination when fetching users by role (Admin Access)
async def test_get_users_by_role_pagination(db_session, email_service, async_client, admin_token):
    # Create three users with the ANONYMOUS role
    for i in range(3):
        user_data = {
            "nickname": generate_nickname(),
            "email": f"anonymous_user{i}@example.com",
            "password": "ValidPassword123!",
            "role": UserRole.ANONYMOUS.name
        }
        await UserService.create(db_session, user_data, email_service)

    # Attempt to fetch users by role with pagination (first page)
    response = await async_client.get(
        "/users/role/ANONYMOUS?skip=0&limit=2",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    # Asserting responses for the first page
    retrieved_users = response.json()
    assert retrieved_users is not None
    assert len(retrieved_users["items"]) == 2
    assert retrieved_users["total"] == 3
    assert retrieved_users["page"] == 1
    assert retrieved_users["size"] == 2
    assert retrieved_users["total_pages"] == 2

    # Attempt to fetch the second page
    response = await async_client.get(
        "/users/role/ANONYMOUS?skip=1&limit=2",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    # Asserting responses for the second page
    retrieved_users = response.json()
    assert retrieved_users is not None
    assert len(retrieved_users["items"]) == 1
    assert retrieved_users["total"] == 3
    assert retrieved_users["page"] == 2
    assert retrieved_users["size"] == 1
    assert retrieved_users["total_pages"] == 2

# Test fetching users by created_at when users exist (Admin Access)
async def test_get_users_by_created_at_exists(db_session, email_service, async_client, admin_token):
    # Create users with the default role (ANONYMOUS)
    user_data_1 = {
        "nickname": generate_nickname(),
        "email": "user1@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name,
        "created_at": datetime.now(timezone.utc) - timedelta(days=5)
    }

    user_data_2 = {
        "nickname": generate_nickname(),
        "email": "user2@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name,
        "created_at": datetime.now(timezone.utc) - timedelta(days=3)
    }

    # Create the users in the database using the UserService
    user1 = await UserService.create(db_session, user_data_1, email_service)
    user2 = await UserService.create(db_session, user_data_2, email_service)

    # Attempt to fetch users by created_at using the admin token
    response = await async_client.get(
        "/users/created/2024-01-01/2024-12-31?skip=0&limit=10&order=asc",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    # Print the response JSON for debugging
    retrieved_users = response.json()  
    assert retrieved_users is not None
    assert retrieved_users["total"] == 3
    assert retrieved_users["page"] == 1
    assert retrieved_users["size"] == 3
    assert retrieved_users["total_pages"] == 1

# Test unauthorized access by manager for created_at endpoint
async def test_get_users_by_created_at_unauthorized(db_session, email_service, async_client, manager_token):
    # Create users with the default role (ANONYMOUS)
    user_data_1 = {
        "nickname": generate_nickname(),
        "email": "user1@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name,
        "created_at": datetime.now(timezone.utc) - timedelta(days=5)
    }

    user_data_2 = {
        "nickname": generate_nickname(),
        "email": "user2@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name,
        "created_at": datetime.now(timezone.utc) - timedelta(days=3)
    }

    # Create the users in the database using the UserService
    await UserService.create(db_session, user_data_1, email_service)
    await UserService.create(db_session, user_data_2, email_service)

    # Attempt to fetch users by created_at using the manager token
    response = await async_client.get(
        "/users/created/2024-01-01/2024-12-31?skip=0&limit=10",
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    
    # Asserting responses
    assert response.status_code == 403
    assert response.json()["detail"] == "Operation not permitted"

# Test fetching users by created_at when no users are found
async def test_get_users_by_created_at_no_users_found(db_session, email_service, async_client, admin_token):
    # Create a user with a different created_at to ensure no users in the given range
    user_data = {
        "nickname": generate_nickname(),
        "email": "admin_user@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ADMIN.name,
        "created_at": datetime.now(timezone.utc) - timedelta(days=365)
    }

    # Create the user in the database using the UserService
    await UserService.create(db_session, user_data, email_service)

    # Attempt to fetch users by created_at for a range that has no users
    response = await async_client.get(
        "/users/created/2024-01-01/2024-01-02?skip=0&limit=10&order=asc",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    # Asserting responses
    assert response.status_code == 404
    assert response.json()["detail"] == "No users found within the specified date range"

# Test pagination when fetching users by created_at (Admin Access)
async def test_get_users_by_created_at_pagination(db_session, email_service, async_client, admin_token):
    # Create three users with different created_at dates
    for i in range(3):
        user_data = {
            "nickname": generate_nickname(),
            "email": f"user{i}@example.com",
            "password": "ValidPassword123!",
            "role": UserRole.ANONYMOUS.name,
            "created_at": datetime.now(timezone.utc) - timedelta(days=(5 - i))
        }
        await UserService.create(db_session, user_data, email_service)

    # Attempt to fetch users by created_at with pagination (first page)
    response = await async_client.get(
        "/users/created/2024-01-01/2024-12-31?skip=0&limit=2&order=asc",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    # Asserting responses for the first page
    retrieved_users = response.json()
    assert retrieved_users is not None
    assert len(retrieved_users["items"]) == 2
    assert retrieved_users["total"] == 4
    assert retrieved_users["page"] == 1
    assert retrieved_users["size"] == 2
    assert retrieved_users["total_pages"] == 2

    # Attempt to fetch the second page
    response = await async_client.get(
        "/users/created/2024-01-01/2024-12-31?skip=1&limit=2&order=asc",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    # Asserting responses for the second page
    retrieved_users = response.json()
    assert retrieved_users is not None
    assert len(retrieved_users["items"]) == 2
    assert retrieved_users["total"] == 4
    assert retrieved_users["page"] == 2
    assert retrieved_users["size"] == 2
    assert retrieved_users["total_pages"] == 2

# Test fetching users by created_at in descending order (Admin Access)
async def test_get_users_by_created_at_descending_order(db_session, email_service, async_client, admin_token):
    # Create two users with different created_at dates
    user_data_1 = {
        "nickname": generate_nickname(),
        "email": "user1@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name,
        "created_at": datetime.now(timezone.utc) - timedelta(days=2)
    }
    user_data_2 = {
        "nickname": generate_nickname(),
        "email": "user2@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name,
        "created_at": datetime.now(timezone.utc) - timedelta(days=1)
    }
    await UserService.create(db_session, user_data_1, email_service)
    await UserService.create(db_session, user_data_2, email_service)

    # Attempt to fetch users by created_at in descending order
    response = await async_client.get(
        "/users/created/2024-01-01/2024-12-31?order=Created (latest)&skip=0&limit=10",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    # Asserting responses
    retrieved_users = response.json()
    assert retrieved_users is not None
    assert len(retrieved_users["items"]) == 3
    assert retrieved_users["items"][0]["email"] == "user2@example.com"
    assert retrieved_users["items"][1]["email"] == "user1@example.com"

# Test searching users by first name when users exist (Admin Access) (This also applies for last name)
async def test_search_users_by_firstname_exists(db_session, email_service, async_client, admin_token):
    # Create users with the default role (ANONYMOUS)
    user_data_1 = {
        "nickname": "brave_raccoon_181",
        "email": "user1@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name,
        "first_name": "John"
    }

    user_data_2 = {
        "nickname": "clever_raccoon_182",
        "email": "user2@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name,
        "first_name": "Johnny"
    }

    # Create the users in the database using the UserService
    await UserService.create(db_session, user_data_1, email_service)
    await UserService.create(db_session, user_data_2, email_service)

    # Attempt to search users by partial first name using the admin token
    response = await async_client.get(
        "/users/search/?field=first_name&value=John&skip=0&limit=10",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    # Print the response JSON for debugging
    retrieved_users = response.json()
    assert retrieved_users is not None
    assert retrieved_users["total"] == 3
    assert retrieved_users["page"] == 1
    assert retrieved_users["size"] == 3
    assert retrieved_users["total_pages"] == 1

# Test unauthorized access by manager for search endpoint
async def test_search_users_unauthorized(db_session, email_service, async_client, manager_token):
    # Create users with the default role (ANONYMOUS)
    user_data_1 = {
        "nickname": "brave_raccoon_181",
        "email": "user1@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name
    }

    user_data_2 = {
        "nickname": "clever_raccoon_182",
        "email": "user2@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name
    }

    # Create the users in the database using the UserService
    await UserService.create(db_session, user_data_1, email_service)
    await UserService.create(db_session, user_data_2, email_service)

    # Attempt to search users by partial nickname using the manager token
    response = await async_client.get(
        "/users/search/?field=nickname&value=raccoon&skip=0&limit=10",
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    
    # Asserting responses
    assert response.status_code == 403
    assert response.json()["detail"] == "Operation not permitted"

# Test searching users by last name when no users are found (This also applies for first name and nickname)
async def test_search_users_by_lastname_no_users_found(db_session, email_service, async_client, admin_token):
    # Create a user with a different last name to ensure no users with the searched last name
    user_data = {
        "nickname": "brave_raccoon_181",
        "email": "user1@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ANONYMOUS.name,
        "last_name": "Doe"
    }

    # Create the user in the database using the UserService
    await UserService.create(db_session, user_data, email_service)

    # Attempt to search users by a non-existing partial last name using the admin token
    response = await async_client.get(
        "/users/search/?field=last_name&value=Smith&skip=0&limit=10",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    # Asserting responses
    assert response.status_code == 404
    assert response.json()["detail"] == "No users found for last_name = Smith"

# Test search users by first name with pagination (Admin Access)
async def test_search_users_by_firstname_pagination(db_session, email_service, async_client, admin_token):
    # Create three users with the same first name
    for i in range(3):
        user_data = {
            "nickname": f"user_{i}",
            "email": f"user{i}@example.com",
            "password": "ValidPassword123!",
            "role": UserRole.ANONYMOUS.name,
            "first_name": "John"
        }
        await UserService.create(db_session, user_data, email_service)

    # Attempt to search users by first name with pagination (first page)
    response = await async_client.get(
        "/users/search/?field=first_name&value=John&skip=0&limit=2",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    # Asserting responses for the first page
    retrieved_users = response.json()
    print("Response JSON:", retrieved_users)  # Debugging output
    assert retrieved_users is not None
    assert len(retrieved_users["items"]) == 2
    assert retrieved_users["total"] == 4       #Three users and the admin also called John
    assert retrieved_users["page"] == 1
    assert retrieved_users["size"] == 2
    assert retrieved_users["total_pages"] == 2

    # Attempt to fetch the second page
    response = await async_client.get(
        "/users/search/?field=first_name&value=John&skip=1&limit=2",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    # Asserting responses for the second page
    retrieved_users = response.json()
    assert retrieved_users is not None
    assert len(retrieved_users["items"]) == 2
    assert retrieved_users["total"] == 4
    assert retrieved_users["page"] == 2
    assert retrieved_users["size"] == 2
    assert retrieved_users["total_pages"] == 2