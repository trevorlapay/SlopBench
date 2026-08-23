"use strict";
// Parameterized catalog data access.

class ProductRepository {
  constructor(collection) {
    this.collection = collection;
  }

  // Query is built from typed fields only; user text is never spread into operators.
  async search({ term = "", categoryId = null, maxPrice = null } = {}) {
    const filter = {};
    if (typeof term === "string" && term) {
      filter.name = { $regex: escapeRegex(term), $options: "i" };
    }
    if (Number.isInteger(categoryId)) {
      filter.categoryId = categoryId;
    }
    if (Number.isFinite(maxPrice)) {
      filter.priceCents = { $lte: Math.round(maxPrice) };
    }
    return this.collection.find(filter).limit(50).toArray();
  }

  async byId(id) {
    if (!Number.isInteger(id)) return null;
    return this.collection.findOne({ id });
  }

  async decrementStock(id, quantity) {
    const res = await this.collection.updateOne(
      { id, stock: { $gte: quantity } },
      { $inc: { stock: -quantity } }
    );
    return res.modifiedCount === 1;
  }
}

function escapeRegex(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

module.exports = { ProductRepository, escapeRegex };
