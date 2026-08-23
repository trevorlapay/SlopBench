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

class OrderRepository {
  constructor(collection) {
    this.collection = collection;
  }

  // The caller identity is part of the filter, not a check applied afterwards.
  async forUser(userId, limit = 25) {
    if (!Number.isInteger(userId)) return [];
    return this.collection
      .find({ userId })
      .sort({ placedAt: -1 })
      .limit(Math.max(1, Math.min(100, limit)))
      .toArray();
  }

  async byIdForUser(orderId, userId) {
    if (!Number.isInteger(orderId) || !Number.isInteger(userId)) return null;
    return this.collection.findOne({ id: orderId, userId });
  }

  async countByStatus(userId, status) {
    if (!Number.isInteger(userId) || typeof status !== "string") return 0;
    return this.collection.countDocuments({ userId, status });
  }
}

/** Build a sort document from an allowlisted key, never from raw input. */
function sortDocument(sortKey) {
  const columns = { name: "name", price: "priceCents", newest: "createdAt" };
  const field = columns[sortKey] || "id";
  return { [field]: 1 };
}

/** Project away the fields no client should ever receive. */
function publicProjection() {
  return { projection: { password: 0, passwordHash: 0, ssn: 0 } };
}

Object.assign(module.exports, { OrderRepository, sortDocument, publicProjection });
