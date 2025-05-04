import concurrent.futures
import random
import secrets
import string
import threading
import time
import os

from datetime import datetime
from uuid import uuid4
from tqdm import trange, tqdm

import requests

BASE_URL = os.getenv("BASE_URL", "http://localhost:8888")


### GET
def get_users():
    res = requests.get(f"{BASE_URL}/users")
    assert res.status_code == 200
    return res.json()


def get_posts():
    res = requests.get(f"{BASE_URL}/posts")
    assert res.status_code == 200
    return res.json()


### INSERT
def create_user(user_id: str = None):
    res = requests.post(
        f"{BASE_URL}/users",
        json={
            "id": user_id or uuid4().hex,
            "username": "".join(random.choices(string.ascii_letters, k=10)),
            "name": "".join(random.choices(string.ascii_letters, k=10)),
            "password_hash": secrets.token_hex(16),
            "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
        },
    )
    assert res.status_code == 200


def create_post(user_id: str):
    res = requests.post(
        f"{BASE_URL}/posts",
        json={
            "id": uuid4().hex,
            "user_id": user_id,
            "content": "".join(random.choices(string.ascii_letters, k=64)),
            "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
        },
    )
    assert res.status_code == 200


def create_user_and_posts(n_posts: int = 10):
    user_id = uuid4().hex
    create_user(user_id)

    for _ in range(n_posts):
        create_post(user_id)


### UPDATE
def update_user_name(user_id: str, check_update: bool = False):
    # Get user data
    res_user = requests.get(f"{BASE_URL}/users/{user_id}")
    assert res_user.status_code == 200
    user = res_user.json()

    old_value = user["name"]
    new_value = "".join(random.choices(string.ascii_letters, k=10))

    # Request update
    res = requests.patch(
        f"{BASE_URL}/users/{user_id}", json={"name": [old_value, new_value]}
    )
    assert res.status_code == 200

    if check_update:
        # Check user
        res_user = requests.get(f"{BASE_URL}/users/{user_id}")
        assert res_user.status_code == 200
        user = res_user.json()

        assert user["name"] == new_value


def update_user_username(user_id: str, check_update: bool = False):
    # Get user data
    res_user = requests.get(f"{BASE_URL}/users/{user_id}")
    assert res_user.status_code == 200
    user = res_user.json()

    old_value = user["username"]
    new_value = "".join(random.choices(string.ascii_letters, k=10))

    # Request update
    res = requests.patch(
        f"{BASE_URL}/users/{user_id}", json={"username": [old_value, new_value]}
    )
    assert res.status_code == 200

    if check_update:
        # Check user
        res_user = requests.get(f"{BASE_URL}/users/{user_id}")
        assert res_user.status_code == 200
        user = res_user.json()

        assert user["username"] == new_value


def update_post_content(post_id: str, check_update: bool = False):
    # Get post data
    res_post = requests.get(f"{BASE_URL}/posts/{post_id}")
    assert res_post.status_code == 200
    post = res_post.json()

    old_value = post["content"]
    new_value = "".join(random.choices(string.ascii_letters, k=64))

    # Request update
    res = requests.patch(
        f"{BASE_URL}/posts/{post_id}", json={"content": [old_value, new_value]}
    )
    assert res.status_code == 200

    if check_update:
        # Check post
        res_post = requests.get(f"{BASE_URL}/posts/{post_id}")
        assert res_post.status_code == 200
        post = res_post.json()

        assert post["content"] == new_value


### DELETE
def delete_user(user_id: str):
    res = requests.delete(f"{BASE_URL}/users/{user_id}")
    assert res.status_code


def delete_post(post_id: str):
    res = requests.delete(f"{BASE_URL}/posts/{post_id}")
    assert res.status_code


def run(n_workers: int = 1):
    speeds = {}

    for _ in trange(100, desc="Setup"):
        create_user_and_posts()

    for fn in [get_users, get_posts, create_user, create_user_and_posts]:
        name = fn.__name__
        futures = []
        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as pool:
            for _ in trange(1000, desc=name):
                pool.submit(fn)

        concurrent.futures.wait(futures)
        end_time = time.time()
        speeds[name] = end_time - start_time  # ms per request

    users = get_users()[:1000]
    posts = get_posts()[:1000]
    assert len(users) == 1000
    assert len(posts) == 1000

    ### CREATE POSTS FOR USER
    futures = []
    start_time = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as pool:
        for user in tqdm(users, desc="create_post"):
            pool.submit(create_post, user["id"])

    concurrent.futures.wait(futures)
    end_time = time.time()
    speeds["create_post"] = end_time - start_time  # ms per request

    # UPDATE + DELETE
    for fn, objs in zip(
        [
            update_user_name,
            update_user_username,
            update_post_content,
            delete_user,
            delete_post,
        ],
        [users, users, posts, users, posts],
    ):
        name = fn.__name__
        futures = []
        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as pool:
            for obj in tqdm(objs, desc=name):
                pool.submit(fn, obj["id"])

        end_time = time.time()
        speeds[name] = end_time - start_time  # ms per request

    ### DELETE EVERYTHING FROM THE DATABASE
    for user in get_users():
        delete_user(user["id"])

    for post in get_posts():
        delete_post(post["id"])

    return speeds


### RUN TESTS
def main():
    speeds_st = run(1)
    speeds_mt = run(100)

    print("ST", speeds_st)
    print("MT", speeds_mt)


if __name__ == "__main__":
    main()
