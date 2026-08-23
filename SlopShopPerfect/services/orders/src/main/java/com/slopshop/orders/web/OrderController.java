package com.slopshop.orders.web;

import com.slopshop.orders.domain.Order;
import com.slopshop.orders.persistence.OrderRepository;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Order endpoints.
 *
 * <p>The customer identity is taken from the validated JWT subject.
 */
@RestController
@RequestMapping("/v1/orders")
@Validated
public class OrderController {

    private static final Logger log = LoggerFactory.getLogger(OrderController.class);

    private final OrderRepository orders;

    public OrderController(OrderRepository orders) {
        this.orders = orders;
    }

    /** Body accepted by the transition endpoint. */
    public record TransitionRequest(
            @NotNull @Pattern(regexp = "AUTHORISED|FULFILLING|SHIPPED|CANCELLED|REFUNDED")
            String status) {
    }

    private static UUID subjectOf(Jwt principal) {
        return UUID.fromString(principal.getSubject());
    }

    @GetMapping
    public List<Order> list(
            @AuthenticationPrincipal Jwt principal,
            @RequestParam(defaultValue = "newest")
            @Pattern(regexp = "newest|oldest|total_desc|total_asc") String sort,
            @RequestParam(defaultValue = "25") @Min(1) @Max(100) int limit,
            @RequestParam(defaultValue = "0") @Min(0) int offset) {

        return orders.listForCustomer(subjectOf(principal), sort, limit, offset);
    }

    @GetMapping("/{orderId}")
    public ResponseEntity<Order> get(
            @AuthenticationPrincipal Jwt principal, @PathVariable UUID orderId) {

        return orders.findForCustomer(orderId, subjectOf(principal))
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/{orderId}/transitions")
    public Map<String, String> transition(
            @AuthenticationPrincipal Jwt principal,
            @PathVariable UUID orderId,
            @RequestBody TransitionRequest body) {

        UUID customerId = subjectOf(principal);
        Order.Status next = Order.Status.valueOf(body.status());
        Order.Status applied = orders.transition(orderId, customerId, next);

        log.info("order transitioned orderId={} status={}", orderId, applied);
        return Map.of("status", applied.name());
    }

    @ExceptionHandler(OrderRepository.OrderNotFoundException.class)
    public ResponseEntity<Map<String, String>> notFound() {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "not_found"));
    }

    @ExceptionHandler(OrderRepository.IllegalStateTransitionException.class)
    public ResponseEntity<Map<String, String>> badTransition(
            OrderRepository.IllegalStateTransitionException e) {

        log.info("rejected order transition: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(Map.of("error", "illegal_transition"));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> badRequest() {
        return ResponseEntity.badRequest().body(Map.of("error", "invalid_request"));
    }
}
