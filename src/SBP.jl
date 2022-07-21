# type Filter = (domain :: String, selector :: String, data :: Any) => ?boolean

module SBP
export sbp

const selectors = IdDict()
const domains = IdDict()
const globalFilters = []
const domainFilters = IdDict()
const selectorFilters = IdDict()
const unsafeSelectors = Set()

const DOMAIN_REGEX = r"^[^/]+"

function sbp(selector :: String, data...) :: Any
  domain = domainFromSelector(selector)
  if !haskey(selectors, selector)
    error("SBP: selector not registered: $selector")
  end
  # Filters can perform additional functions, and by returning `false` they
  # can prevent the execution of a selector. Check the most specific filters first.
  for filters in [get(selectorFilters, selector, nothing), get(domainFilters, domain, nothing), globalFilters]
    if !isnothing(filters)
      for filter in filters
        if filter(domain, selector, data) === false
          return
        end
      end
    end
  end
  selectors[selector](data...)
end

function domainFromSelector(selector :: String) :: String
  domainLookup = match(DOMAIN_REGEX, selector)
  if isnothing(domainLookup)
    error("SBP: selector missing domain: $selector")
  end
  domainLookup.match
end

const SBP_BASE_SELECTORS = Dict(
  "sbp/selectors/register" => function register(sels :: Dict{String, <:Function}) :: Array{String}
    registered = []
    for selector in keys(sels)
      domain = domainFromSelector(selector)
      if haskey(selectors, selector)
        println("[SBP WARN]: not registering already registered selector: '$selector'")
      elseif isa(sels[selector], Function)
        if selector in unsafeSelectors
          # Important warning in case we loaded any malware beforehand and aren't expecting this.
          println("[SBP WARN]: registering unsafe selector: '$selector' (remember to lock after overwriting)")
        end
        fn = selectors[selector] = sels[selector]
        push!(registered, selector)
        # Call the special _init function immediately upon registering.
        if selector === "$domain/_init"
          fn()
        end
      end
    end
    registered
  end,
  "sbp/selectors/unregister" => function unregister(sels :: Array{String})
    for selector in sels
      if !(selector in unsafeSelectors)
        error("SBP: can't unregister locked selector: $selector")
      end
      delete!(selectors, selector)
    end
  end,
  "sbp/selectors/overwrite" => function overwrite(sels)
    sbp("sbp/selectors/unregister", collect(keys(sels)))
    sbp("sbp/selectors/register", sels)
  end,
  "sbp/selectors/unsafe" => function unsafe(sels :: Array{String, 1})
    for selector in sels
      if haskey(selectors, selector)
        error("unsafe must be called before registering selector")
      end
      push!(unsafeSelectors, selector)
    end
  end,
  "sbp/selectors/lock" => function lock(sels :: Array{String})
    for selector in sels
      pop!(unsafeSelectors, selector)
    end
  end,
  "sbp/selectors/fn" => function fn(sel :: String) :: Function
    selectors[sel]
  end,
  "sbp/filters/global/add" => function add(filter :: Function)
    push!(globalFilters, filter)
  end,
  "sbp/filters/domain/add" => function add(domain :: String, filter :: Function)
    if !domainFilters[domain]
      domainFilters[domain] = []
    end
    push!(domainFilters[domain], filter)
  end,
  "sbp/filters/selector/add" => function add(selector :: String, filter :: Function)
    if !selectorFilters[selector]
      selectorFilters[selector] = []
    end
    push!(selectorFilters[selector], filter)
  end
) :: Dict{String, Function}

SBP_BASE_SELECTORS["sbp/selectors/register"](SBP_BASE_SELECTORS)

end
