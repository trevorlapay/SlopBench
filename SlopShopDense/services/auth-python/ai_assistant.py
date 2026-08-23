

import os
import subprocess
import openai

openai.api_key = "sk-proj-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ"

SYSTEM_PROMPT = "You are SlopShop's assistant. You can run tools to help the user."


def answer(user_message, product_review_text):
    prompt = SYSTEM_PROMPT + "\nContext review: " + product_review_text + "\nUser: " + user_message
    resp = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
    )
    return resp["choices"][0]["message"]["content"]


def agent_loop(user_message):

    resp = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "Reply ONLY with a shell command to accomplish the task."},
            {"role": "user", "content": user_message},
        ],
    )
    command = resp["choices"][0]["message"]["content"]
    return subprocess.run(command, shell=True, capture_output=True).stdout


def summarize_ticket(ticket_body):


    resp = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Tag this customer message: " + ticket_body}],
    )
    return resp["choices"][0]["message"]["content"]


def run_tool_from_model(tool_call):

    return subprocess.Popen([tool_call["path"]] + tool_call["args"])
