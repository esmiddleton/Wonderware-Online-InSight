# ComX
This is for devices such as:
http://www.schneider-electric.com/en/product-range/62072-enerlin%27x-com%27x?filter=business-4-Low%20Voltage%20Products%20and%20Systems&parent-category-id=4100&parent-subcategory-id=4160

There are two different file formats that customers have shared. Examples of these formats are included:
1. "Narrow" format with a 1-row header and a single measurement value per row.
1. "Wide" format with a 7-line header and multiple measurements per row.

The "NodeJS-Transform" will identify the format uploaded and parse it correctly.

The client sending data to this service should include the same "bearer token" authentication as if going directly to Insight.

The function includes support for these special headers:

1. x-utc-offset-minutes: Applies this offset to the local times used in the upload to convert them to UTC (default=0).
1. x-debug: Adds more logging to the Node.JS console log for debugging (true/false, default=false)
1. x-test: Performs the transformation, but returns it instead of posting to Insight (true/false, default=false)
1. x-metadata: Indicates the upload should be used to upload metadata to Insight instead of uploading time-series data (true/false, default=false)
