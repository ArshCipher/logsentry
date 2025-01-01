 
import pandas as pd
import plotly.express as px
import logging

logger = logging.getLogger(__name__)

class Visualizer:
    """Generate visualizations for suspicious login attempts."""
    def create_heatmap(self, data: list, output_path: str = "sentry_heatmap.html"):
        """Create a heatmap of login attempts by hour and user."""
        if not data:
            logger.info("No data to visualize.")
            return
        try:
            df = pd.DataFrame(data)
            df["hour"] = pd.to_datetime(df["time_range"].str.split(" ").str[0]).dt.hour
            heatmap_data = df.groupby(["hour", "user"]).size().unstack(fill_value=0)
            fig = px.imshow(heatmap_data, title="Suspicious Logins by Hour and User")
            fig.write_html(output_path)
            logger.info(f"Heatmap saved to {output_path}")
        except Exception as e:
            logger.error(f"Visualization failed: {e}")

    def create_geo_plot(self, data: list, output_path: str = "sentry_geo.html"):
        """Create a geographic scatter plot of login attempts."""
        if not data:
            logger.info("No data to visualize.")
            return
        try:
            df = pd.DataFrame(data)
            df = df.dropna(subset=["geo.latitude", "geo.longitude"])
            if df.empty:
                logger.info("No geo data for plotting.")
                return
            fig = px.scatter_geo(
                df,
                lat="geo.latitude",
                lon="geo.longitude",
                hover_name="ip",
                hover_data=["user", "type"],
                title="Suspicious Login Locations"
            )
            fig.write_html(output_path)
            logger.info(f"Geo plot saved to {output_path}")
        except Exception as e:
            logger.error(f"Geo plot failed: {e}")