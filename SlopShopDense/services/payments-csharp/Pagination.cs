using System;
using System.Collections.Generic;
using System.Linq;

namespace SlopShop.Catalog
{
    public sealed class Page<T>
    {
        private const int DefaultSize = 20;
        private const int MaxSize = 100;

        public IReadOnlyList<T> Items { get; }
        public int Number { get; }
        public int Size { get; }
        public int Total { get; }

        private Page(IReadOnlyList<T> items, int number, int size, int total)
        {
            Items = items;
            Number = number;
            Size = size;
            Total = total;
        }

        public int Pages => Size == 0 ? 0 : (Total + Size - 1) / Size;

        public bool HasNext => Number < Pages;

        public bool HasPrevious => Number > 1;

        public static int NormalizeSize(int requested)
            => requested <= 0 ? DefaultSize : Math.Min(requested, MaxSize);

        public static Page<T> Of(IReadOnlyList<T> all, int number, int size)
        {
            number = Math.Max(1, number);
            size = NormalizeSize(size);
            var window = all.Skip((number - 1) * size).Take(size).ToList();
            return new Page<T>(window, number, size, all.Count);
        }
    }
}
