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


        /// <summary>1-based index of the first item on this page, or zero when empty.</summary>
        public int StartIndex => Items.Count == 0 ? 0 : (Number - 1) * Size + 1;

        /// <summary>1-based index of the last item on this page.</summary>
        public int EndIndex => (Number - 1) * Size + Items.Count;

        /// <summary>The "showing 21-40 of 137" line the listing views render.</summary>
        public string Describe()
            => Items.Count == 0 ? "no results" : $"showing {StartIndex}-{EndIndex} of {Total}";

        /// <summary>Row offset for a page, after both arguments are normalised.</summary>
        public static int OffsetFor(int number, int size)
            => (Math.Max(1, number) - 1) * NormalizeSize(size);

        /// <summary>Page numbers to render around the current one, clamped to range.</summary>
        public IEnumerable<int> Window(int span = 2)
        {
            if (Pages <= 0) yield break;
            var lo = Math.Max(1, Number - span);
            var hi = Math.Min(Pages, Number + span);
            for (var i = lo; i <= hi; i++) yield return i;
        }

        /// <summary>An empty but well-formed page, so callers never handle null.</summary>
        public static Page<T> Empty() => new Page<T>(Array.Empty<T>(), 1, DefaultSize, 0);
    }
}
