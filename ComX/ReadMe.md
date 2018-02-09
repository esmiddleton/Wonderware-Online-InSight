# ComX
This is for devices such as:
http://www.schneider-electric.com/en/product-range/62072-enerlin%27x-com%27x?filter=business-4-Low%20Voltage%20Products%20and%20Systems&parent-category-id=4100&parent-subcategory-id=4160

There are two different file formats that customers have shared. Examples of these formats are included:
1. "Narrow" format with a 1-row header and a single measurement value per row.
1. "Wide" format with a 7-line header and multiple measurements per row.

The "NodeJS-Transform" will identify the format uploaded and parse it correctly. The predates InSight's "Extension" support and used an external NodeJS service.
