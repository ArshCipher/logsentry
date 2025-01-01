 
import geoip2.database
import logging

logger = logging.getLogger(__name__)

class GeoResolver:
    """GeoIP resolution for IP addresses."""
    def __init__(self, db_path: str = "GeoLite2-City.mmdb"):
        try:
            self.reader = geoip2.database.Reader(db_path)
        except FileNotFoundError:
            logger.error("GeoIP database missing. Geo features disabled.")
            self.reader = None

    def resolve(self, ip: str) -> dict:
        """Resolve IP to geographic data."""
        if not self.reader:
            return {"country": "Unknown", "city": "Unknown", "latitude": None, "longitude": None}
        try:
            response = self.reader.city(ip)
            return {
                "country": response.country.name or "Unknown",
                "city": response.city.name or "Unknown",
                "latitude": response.location.latitude,
                "longitude": response.location.longitude
            }
        except (geoip2.errors.AddressNotFoundError, ValueError):
            return {"country": "Unknown", "city": "Unknown", "latitude": None, "longitude": None}