# Azure Synapse Analytics Lab

Lab time: 90 minutes

## Wide World Importers

Wide World Importers (WWI) is a wholesale novelty goods importer and distributor operating from the San Francisco bay area.

As a wholesaler, WWI's customers are mostly companies who resell to individuals. WWI sells to retail customers across the United States, including specialty stores, supermarkets, computing stores, tourist attraction shops, and some individuals. WWI sells to other wholesalers via a network of agents who promote the products on WWI's behalf. While all of WWI's customers are currently based in the United States, the company intends to expand into other countries.

WWI buys goods from suppliers, including novelty and toy manufacturers, and other novelty wholesalers. They stock the goods in their WWI warehouse and reorder from suppliers as needed to fulfill customer orders. They also purchase large volumes of packaging materials and sell these in smaller quantities as a convenience for the customers.

Recently WWI started to sell a variety of edible novelties such as chili chocolates. The company previously did not have to handle chilled items. To meet food handling requirements, they must monitor the temperature in their chiller room and any of their trucks that have chiller sections.

## Lab context

Wide World Importers is designing and implementing a Proof of Concept (PoC) for a unified data analytics platform. Their soft goal is to bring siloed teams to work together on a single platform.

In this lab, you will play the role of various persona: a data engineer, a business analyst, and a data scientist. The workspace is already set up to focus on some of the core development capabilities of Azure Synapse Analytics.

By the end of this lab, you will have performed a non-exhaustive list of operations that combine the strength of Big Data and SQL analytics into a single platform.

## Solution architecture

The diagram below provides a unified view of the exercises in the lab and their estimated times for completion.

![Azure Synapse Analytics Lab Exercises](./images/exercises.png "Solution architecture")

## Exercise 1 - Explore the data lake with Azure Synapse SQL On-demand and Azure Synapse Spark

In this exercise, you will explore data using the engine of your choice (SQL or Spark).

Understanding data through data exploration is one of the core challenges faced today by data engineers and data scientists as well. Depending on the data's underlying structure and the specific requirements of the exploration process, different data processing engines will offer varying degrees of performance, complexity, and flexibility.

In Azure Synapse Analytics, you have the possibility of using either the SQL Serverless engine, the big-data Spark engine, or both.

## Exercise 2 - Build a Modern Data Warehouse with Azure Synapse Pipelines

In this exercise, you will use a pipeline with parallel activities to bring data into the Data Lake, transform it, and load it into the Azure Synapse SQL Pool. You will also monitor the progress of the associated tasks.

Once data is properly understood and interpreted, moving it to the various destinations where processing steps occur is the next big task. Any modern data platform must provide a seamless experience for all the typical data wrangling actions like extractions, parsing, joining, standardizing, augmenting, cleansing, consolidating, and filtering.

Azure Synapse Analytics provides two significant categories of features - data flows and data orchestrations (implemented as pipelines). They cover the whole range of needs, from design and development to triggering, execution, and monitoring.
