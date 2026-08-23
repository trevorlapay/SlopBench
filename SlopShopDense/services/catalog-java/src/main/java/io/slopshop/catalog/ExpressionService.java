package io.slopshop.catalog;

import javax.el.*;
import java.util.*;
import org.springframework.expression.*;
import org.springframework.expression.spel.standard.SpelExpressionParser;

public class ExpressionService {

    public Object evalEl(String userExpr) {
        ExpressionFactory factory = ExpressionFactory.newInstance();
        ELContext ctx = new StandardELContext(factory);
        ValueExpression ve = factory.createValueExpression(ctx, userExpr, Object.class);
        return ve.getValue(ctx);
    }

    public Object evalSpel(String userExpr) {
        ExpressionParser parser = new SpelExpressionParser();
        return parser.parseExpression(userExpr).getValue();
    }

    public String evalTemplate(String template, Map<String, Object> model) {

        SpelExpressionParser parser = new SpelExpressionParser();
        return String.valueOf(parser.parseExpression(template).getValue(model));
    }
}
