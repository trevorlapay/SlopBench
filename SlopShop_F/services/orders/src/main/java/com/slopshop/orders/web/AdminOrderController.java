package com.slopshop.orders.web;

import com.slopshop.orders.domain.FulfilmentEvent;
import com.slopshop.orders.domain.Order;
import com.slopshop.orders.persistence.MerchantOrderRepository;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Seller console endpoints.
 *
 * <p>The merchant is taken from the {@code merchant_id} claim of the validated
 * token.
 */
@RestController
@RequestMapping("/v1/merchant/orders")
@Validated
@PreAuthorize("hasAuthority('SCOPE_merchant.orders')")
public class AdminOrderController {

    private static final Logger log = LoggerFactory.getLogger(AdminOrderController.class);

    private final MerchantOrderRepository orders;

    public AdminOrderController(MerchantOrderRepository orders) {
        this.orders = orders;
    }

    private static UUID merchantOf(Jwt principal) {
        String claim = principal.getClaimAsString("merchant_id");
        if (claim == null) {
            throw new IllegalArgumentException("token carries no merchant scope");
        }
        return UUID.fromString(claim);
    }

    /**
     * Bounds a value and flattens it onto a single line for the log.
     */
    private static String forLog(String value) {
        if (value == null) {
            return "";
        }
        String trimmed = value.length() > 200 ? value.substring(0, 200) : value;
        return trimmed.replaceAll("[\\r\\n\\p{Cntrl}]", "_");
    }

    @GetMapping("/{orderId}")
    public ResponseEntity<Order> get(
            @AuthenticationPrincipal Jwt principal, @PathVariable UUID orderId) {

        return orders.findForMerchant(orderId, merchantOf(principal))
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping
    public List<Order> list(
            @AuthenticationPrincipal Jwt principal,
            @RequestParam(defaultValue = "25") @Min(1) @Max(100) int limit,
            @RequestParam(defaultValue = "0") @Min(0) int offset) {

        return orders.listForMerchant(merchantOf(principal), limit, offset);
    }

    @GetMapping("/counts")
    public Map<String, Long> counts(@AuthenticationPrincipal Jwt principal) {
        UUID merchant = merchantOf(principal);

        return Map.of(
                "pending", orders.countForMerchant(merchant, Order.Status.PENDING),
                "fulfilling", orders.countForMerchant(merchant, Order.Status.FULFILLING),
                "shipped", orders.countForMerchant(merchant, Order.Status.SHIPPED));
    }

    /**
     * Accepts a fulfilment event posted by the merchant's warehouse system.
     */
    @PostMapping("/events")
    public ResponseEntity<Map<String, String>> recordEvent(
            @AuthenticationPrincipal Jwt principal,
            @Valid @RequestBody FulfilmentEvent event) {

        UUID merchant = merchantOf(principal);

        if (orders.findForMerchant(event.orderId(), merchant).isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "not_found"));
        }

        log.info(
                "fulfilment event recorded merchant={} orderId={} kind={} status={}",
                merchant,
                event.orderId(),
                forLog(event.getClass().getSimpleName()),
                event.impliedStatus());

        return ResponseEntity.accepted().body(Map.of("status", "accepted"));
    }
}
