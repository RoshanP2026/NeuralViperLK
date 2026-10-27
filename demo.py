import pickle

def get_user(cur, name):
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")

def load(blob):
    return pickle.loads(blob)

def add(a, b):
    return a + b