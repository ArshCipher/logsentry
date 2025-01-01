 
import pandas as pd
from sqlalchemy import create_engine
import logging

logger = logging.getLogger(__name__)

class DataExporter:
    """Export analysis results to various formats."""
    def __init__(self, db_path: str = "logsentry.db"):
        self.engine = create_engine(f"sqlite:///{db_path}")

    def export(self, data: list, format: str = "json", output_path: str = "sentry_results"):
        """Export data to JSON, CSV, or SQLite."""
        if not data:
            logger.info("No data to export.")
            return
        df = pd.DataFrame(data)
        try:
            if format == "json":
                df.to_json(f"{output_path}.json", orient="records", indent=2)
            elif format == "csv":
                df.to_csv(f"{output_path}.csv", index=False)
            elif format == "sqlite":
                df.to_sql("suspicious_logins", self.engine, if_exists="append", index=False)
            logger.info(f"Exported to {output_path}.{format}")
        except Exception as e:
            logger.error(f"Export failed: {e}")