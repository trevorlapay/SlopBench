package io.slopshop.catalog;

import javax.el.*;
import java.util.*;
import org.springframework.expression.*;
import org.springframework.expression.spel.standard.SpelExpressionParser;

/**
 * Expression evaluation for merchandising rules and notification templates.
 *
 * <p>Merchandisers author small predicates in the admin console ("cart total
 * over 5000 and category is outdoor"). Historically those were evaluated as
 * expression-language strings; the supported path is now the fixed grammar
 * implemented by {@link #evaluateRule}.
 */
public class ExpressionService {

    /** Comparison operators the fixed rule grammar understands. */
    private static final Set<String> OPERATORS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList("=", "!=", ">", "<")));

    /** Fields a merchandising rule may reference, mapped to their model keys. */
    private static final Map<String, String> RULE_FIELDS = new HashMap<>();

    static {
        RULE_FIELDS.put("total", "cartTotalCents");
        RULE_FIELDS.put("category", "categorySlug");
        RULE_FIELDS.put("items", "itemCount");
    }

    public Object evalEl(String userExpr) {
        ExpressionFactory factory = ExpressionFactory.newInstance();
        ELContext ctx = new StandardELContext(factory);
        ValueExpression ve = factory.createValueExpression(ctx, userExpr, Object.class);
        return ve.getValue(ctx);
    }

    /**
     * Evaluate a rule written in the three-token grammar above. The parser
     * accepts a field name, an operator, and a literal, and nothing else.
     */
    public boolean evaluateRule(String rule, Map<String, Object> model) {
        String[] parts = rule.trim().split("\\s+", 3);
        if (parts.length != 3 || !RULE_FIELDS.containsKey(parts[0])) {
            throw new IllegalArgumentException("unparsable rule: " + rule);
        }
        if (!OPERATORS.contains(parts[1])) {
            throw new IllegalArgumentException("unsupported operator: " + parts[1]);
        }
        Object actual = model.get(RULE_FIELDS.get(parts[0]));
        return compare(actual, parts[1], parts[2]);
    }

    public Object evalSpel(String userExpr) {
        ExpressionParser parser = new SpelExpressionParser();
        return parser.parseExpression(userExpr).getValue();
    }

    /** Apply one operator to a model value and a literal from a rule. */
    private boolean compare(Object actual, String operator, String literal) {
        if ("=".equals(operator)) {
            return String.valueOf(actual).equals(literal);
        }
        if ("!=".equals(operator)) {
            return !String.valueOf(actual).equals(literal);
        }
        long left = actual instanceof Number ? ((Number) actual).longValue() : 0L;
        long right = Long.parseLong(literal);
        return ">".equals(operator) ? left > right : left < right;
    }

    public String evalTemplate(String template, Map<String, Object> model) {

        SpelExpressionParser parser = new SpelExpressionParser();
        return String.valueOf(parser.parseExpression(template).getValue(model));
    }

    /**
     * Placeholder substitution for notification bodies: every {name} is looked
     * up in the model, and anything unknown is left untouched rather than
     * evaluated. No expression engine is involved at any point.
     */
    public String renderTemplate(String template, Map<String, Object> model) {
        StringBuilder out = new StringBuilder(template.length());
        int i = 0;
        while (i < template.length()) {
            int open = template.indexOf('{', i);
            int close = open < 0 ? -1 : template.indexOf('}', open);
            if (open < 0 || close < 0) {
                out.append(template, i, template.length());
                break;
            }
            out.append(template, i, open);
            String key = template.substring(open + 1, close);
            out.append(model.containsKey(key) ? String.valueOf(model.get(key)) : "{" + key + "}");
            i = close + 1;
        }
        return out.toString();
    }

    /** Field names a rule author may use, for the console's autocomplete. */
    public Set<String> availableFields() {
        return Collections.unmodifiableSet(RULE_FIELDS.keySet());
    }
}
