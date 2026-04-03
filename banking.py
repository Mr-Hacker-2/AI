import os
import json
from datetime import datetime
from fastapi import APIRouter

router = APIRouter(prefix="/banking", tags=["banking"])

BANK_DATA_FILE = "/home/admin/Mr-A-Hacker-pocket-Ai-version-2/banking_data.json"

def load_data():
    if os.path.exists(BANK_DATA_FILE):
        try:
            with open(BANK_DATA_FILE, "r") as f:
                return json.load(f)
        except:
            pass
    return {
        "accounts": [
            {"id": 1, "name": "Main Checking", "account_number": "****4521", "balance": 2547.32, "currency": "USD"},
            {"id": 2, "name": "Savings", "account_number": "****8832", "balance": 5000.00, "currency": "USD"},
        ],
        "transactions": [
            {"id": 1, "date": "2026-03-30", "description": "Direct Deposit", "amount": 1500.00, "type": "credit", "account": "Main Checking", "category": "Income"},
            {"id": 2, "date": "2026-03-29", "description": "Grocery Store", "amount": -89.45, "type": "debit", "account": "Main Checking", "category": "Food"},
            {"id": 3, "date": "2026-03-28", "description": "Electric Bill", "amount": -125.00, "type": "debit", "account": "Main Checking", "category": "Bills"},
            {"id": 4, "date": "2026-03-27", "description": "Gas Station", "amount": -45.00, "type": "debit", "account": "Main Checking", "category": "Transport"},
            {"id": 5, "date": "2026-03-25", "description": "Transfer to Savings", "amount": -200.00, "type": "debit", "account": "Main Checking", "category": "Transfer"},
            {"id": 6, "date": "2026-03-25", "description": "Transfer from Checking", "amount": 200.00, "type": "credit", "account": "Savings", "category": "Transfer"},
            {"id": 7, "date": "2026-03-24", "description": "Netflix", "amount": -15.99, "type": "debit", "account": "Main Checking", "category": "Entertainment"},
            {"id": 8, "date": "2026-03-23", "description": "Restaurant", "amount": -35.50, "type": "debit", "account": "Main Checking", "category": "Food"},
        ],
        "owing": [
            {"id": 1, "person": "John Doe", "amount": 150.00, "reason": "Lunch", "date": "2026-03-28"},
            {"id": 2, "person": "Mom", "amount": 500.00, "reason": "Car repair", "date": "2026-03-20"},
        ],
        "owed_to_me": [
            {"id": 1, "person": "Mike Smith", "amount": 75.00, "reason": "Concert tickets", "date": "2026-03-25"},
            {"id": 2, "person": "Sarah Lee", "amount": 120.00, "reason": "Dinner", "date": "2026-03-22"},
        ],
        "bills": [
            {"id": 1, "name": "Electric Bill", "amount": 125.00, "due_date": "2026-04-01", "paid": false, "category": "Utilities"},
            {"id": 2, "name": "Internet", "amount": 79.99, "due_date": "2026-04-05", "paid": false, "category": "Services"},
            {"id": 3, "name": "Rent", "amount": 1200.00, "due_date": "2026-04-01", "paid": false, "category": "Housing"},
            {"id": 4, "name": "Car Insurance", "amount": 150.00, "due_date": "2026-04-10", "paid": true, "category": "Insurance"},
        ],
        "savings_goals": [
            {"id": 1, "name": "Emergency Fund", "target": 5000.00, "current": 2500.00, "icon": "🛡️"},
            {"id": 2, "name": "Vacation", "target": 2000.00, "current": 800.00, "icon": "✈️"},
            {"id": 3, "name": "New Phone", "target": 1000.00, "current": 450.00, "icon": "📱"},
        ]
    }

def save_data(data):
    with open(BANK_DATA_FILE, "w") as f:
        json.dump(data, f)

@router.get("/accounts")
async def get_accounts():
    data = load_data()
    return data

@router.post("/transaction")
async def add_transaction(request: dict):
    amount = float(request.get("amount", 0))
    description = request.get("description", "")
    trans_type = request.get("type", "debit")
    account_name = request.get("account", "My Checking")
    category = request.get("category", "Other")
    
    data = load_data()
    
    signed_amount = amount if trans_type == "credit" else -amount
    
    for account in data["accounts"]:
        if account["name"] == account_name:
            account["balance"] += signed_amount
            break
    
    transaction = {
        "id": len(data["transactions"]) + 1,
        "date": datetime.now().strftime("%Y-%m-%d"),
        "description": description,
        "amount": signed_amount,
        "type": trans_type,
        "account": account_name,
        "category": category
    }
    data["transactions"].insert(0, transaction)
    
    save_data(data)
    return {"status": "success", "data": data}

@router.post("/owing")
async def add_owing(request: dict):
    person = request.get("person", "")
    amount = float(request.get("amount", 0))
    reason = request.get("reason", "")
    
    data = load_data()
    
    owing = {
        "id": len(data.get("owing", [])) + 1,
        "person": person,
        "amount": amount,
        "reason": reason,
        "date": datetime.now().strftime("%Y-%m-%d")
    }
    
    if "owing" not in data:
        data["owing"] = []
    data["owing"].insert(0, owing)
    
    save_data(data)
    return {"status": "success", "data": data}

@router.delete("/owing/{owing_id}")
async def delete_owing(owing_id: int):
    data = load_data()
    data["owing"] = [o for o in data.get("owing", []) if o["id"] != owing_id]
    save_data(data)
    return {"status": "success", "data": data}

@router.post("/owed_to_me")
async def add_owed_to_me(request: dict):
    person = request.get("person", "")
    amount = float(request.get("amount", 0))
    reason = request.get("reason", "")
    
    data = load_data()
    
    owed = {
        "id": len(data.get("owed_to_me", [])) + 1,
        "person": person,
        "amount": amount,
        "reason": reason,
        "date": datetime.now().strftime("%Y-%m-%d")
    }
    
    if "owed_to_me" not in data:
        data["owed_to_me"] = []
    data["owed_to_me"].insert(0, owed)
    
    save_data(data)
    return {"status": "success", "data": data}

@router.delete("/owed_to_me/{owed_id}")
async def delete_owed_to_me(owed_id: int):
    data = load_data()
    data["owed_to_me"] = [o for o in data.get("owed_to_me", []) if o["id"] != owed_id]
    save_data(data)
    return {"status": "success", "data": data}

@router.post("/bills")
async def add_bill(request: dict):
    name = request.get("name", "")
    amount = float(request.get("amount", 0))
    due_date = request.get("due_date", "")
    category = request.get("category", "Other")
    
    data = load_data()
    
    bill = {
        "id": len(data.get("bills", [])) + 1,
        "name": name,
        "amount": amount,
        "due_date": due_date,
        "paid": False,
        "category": category
    }
    
    if "bills" not in data:
        data["bills"] = []
    data["bills"].append(bill)
    
    save_data(data)
    return {"status": "success", "data": data}

@router.put("/bills/{bill_id}")
async def toggle_bill_paid(bill_id: int):
    data = load_data()
    for bill in data.get("bills", []):
        if bill["id"] == bill_id:
            bill["paid"] = not bill["paid"]
            break
    save_data(data)
    return {"status": "success", "data": data}

@router.delete("/bills/{bill_id}")
async def delete_bill(bill_id: int):
    data = load_data()
    data["bills"] = [b for b in data.get("bills", []) if b["id"] != bill_id]
    save_data(data)
    return {"status": "success", "data": data}

@router.post("/savings")
async def add_savings_goal(request: dict):
    name = request.get("name", "")
    target = float(request.get("target", 0))
    icon = request.get("icon", "💰")
    
    data = load_data()
    
    goal = {
        "id": len(data.get("savings_goals", [])) + 1,
        "name": name,
        "target": target,
        "current": 0,
        "icon": icon
    }
    
    if "savings_goals" not in data:
        data["savings_goals"] = []
    data["savings_goals"].append(goal)
    
    save_data(data)
    return {"status": "success", "data": data}

@router.post("/savings/{goal_id}/add")
async def add_to_savings_goal(goal_id: int, request: dict):
    amount = float(request.get("amount", 0))
    
    data = load_data()
    for goal in data.get("savings_goals", []):
        if goal["id"] == goal_id:
            goal["current"] = min(goal["current"] + amount, goal["target"])
            break
    
    checking_acc = next((a for a in data["accounts"] if "Checking" in a["name"]), None)
    savings_acc = next((a for a in data["accounts"] if "Savings" in a["name"]), None)
    
    if checking_acc and savings_acc and checking_acc["balance"] >= amount:
        checking_acc["balance"] -= amount
        savings_acc["balance"] += amount
        
        transaction = {
            "id": len(data["transactions"]) + 1,
            "date": datetime.now().strftime("%Y-%m-%d"),
            "description": f"Transfer to Savings",
            "amount": -amount,
            "type": "debit",
            "account": checking_acc["name"],
            "category": "Transfer"
        }
        data["transactions"].insert(0, transaction)
        
        transaction2 = {
            "id": len(data["transactions"]) + 2,
            "date": datetime.now().strftime("%Y-%m-%d"),
            "description": f"Transfer from Checking",
            "amount": amount,
            "type": "credit",
            "account": savings_acc["name"],
            "category": "Transfer"
        }
        data["transactions"].insert(0, transaction2)
    
    save_data(data)
    return {"status": "success", "data": data}

@router.delete("/savings/{goal_id}")
async def delete_savings_goal(goal_id: int):
    data = load_data()
    data["savings_goals"] = [g for g in data.get("savings_goals", []) if g["id"] != goal_id]
    save_data(data)
    return {"status": "success", "data": data}