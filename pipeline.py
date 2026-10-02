from src.vulnpulse.pipeline import (
    parse_arguments,
    run_pipeline,
)


if __name__ == "__main__":
    args = parse_arguments()
    run_pipeline(
        scan_name=args.scan_name
    )