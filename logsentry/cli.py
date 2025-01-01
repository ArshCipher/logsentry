 
import asyncio
import uvloop
import typer
import logging
from .core import LogParser
from .ml import AnomalyDetector
from .geo import GeoResolver
from .export import DataExporter
from .viz import Visualizer
from .firewall import Firewall
from .watcher import LogMonitor

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
logger = logging.getLogger(__name__)
app = typer.Typer()

@app.command()
def run(
    log_file: str = typer.Argument("logs/auth.log"),
    time_window: int = typer.Option(10, help="Time window (minutes) for brute-force detection"),
    max_attempts: int = typer.Option(5, help="Max attempts for brute-force detection"),
    export_format: str = typer.Option("json", help="Export format: json, csv, sqlite"),
    block_ips: bool = typer.Option(False, help="Block suspicious IPs"),
    geo_plot: bool = typer.Option(True, help="Generate geo plot"),
):
    """Run LogSentry to detect suspicious login attempts."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    parser = LogParser()
    ml_detector = AnomalyDetector()
    geo_resolver = GeoResolver()
    exporter = DataExporter()
    visualizer = Visualizer()
    firewall = Firewall()

    async def process_log(file_path: str):
        try:
            await parser.process_log(file_path)
            suspicious = parser.analyze(time_window, max_attempts)
            ml_detector.train(parser.attempts)
            suspicious.extend(ml_detector.detect(parser.attempts))

            # Enrich with GeoIP data
            for entry in suspicious:
                entry["geo"] = geo_resolver.resolve(entry["ip"])

            if suspicious:
                for entry in suspicious:
                    logger.info(
                        f"Suspicious: User={entry['user']}, IP={entry['ip']} "
                        f"({entry['geo']['country']}/{entry['geo']['city']}), "
                        f"Type={entry['type']}, Time={entry['time_range']}"
                    )
                    if block_ips and entry["type"] == "brute_force":
                        firewall.block_ip(entry["ip"])
                exporter.export(suspicious, export_format)
                visualizer.create_heatmap(suspicious)
                if geo_plot:
                    visualizer.create_geo_plot(suspicious)
            else:
                logger.info("No suspicious activity detected.")
        except Exception as e:
            logger.error(f"Processing failed: {e}")

    # Initial run
    asyncio.run(process_log(log_file))

    # Start real-time monitoring
    monitor = LogMonitor(process_log)
    observer = monitor.start(log_file)
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        observer.stop()
        logger.info("Monitoring stopped.")
    observer.join()

if __name__ == "__main__":
    app()