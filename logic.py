from datetime import datetime
from dataclasses import dataclass
import datetime

# * Transaction Types

BOUGHT = 1
SOLD = 0

@dataclass(frozen=True)
class Transaction:
    id: int
    user_id: int
    coin_name: str
    coin_symbol: str
    transaction_type: int
    amount: int
    time_transacted: datetime
    time_created: datetime
    price_purchased_at: float
    no_of_coins: float


def format_db_row_to_transaction(row):
    return Transaction( 
       id=row[0],
       coin_name=row[2],
       transaction_type=row[4],
       amount=row[5]/100,
       time_transacted=row[6].strftime("%Y/%m/%d"),
       time_created=row[7].strftime("%Y/%m/%d"),
       price_purchased_at=float(row[8]),
    )